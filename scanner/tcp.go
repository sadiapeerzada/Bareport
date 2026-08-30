package scanner

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// job is one unit of work handed to a worker goroutine: probe one
// host:port pair.
type job struct {
	host string
	port int
}

// ScanTCP runs a concurrent TCP connect scan across every host in
// `hosts` and every port in `ports`, using a fixed-size worker pool.
//
// Why worker-pool + buffered channel rather than "one goroutine per
// port": scanning even a /24 on 100 ports is 25,600 dials. Unbounded
// goroutines would exhaust file descriptors and swamp the local
// ephemeral-port range almost immediately. A bounded pool of `workers`
// goroutines pulling from a channel gives us predictable, tunable
// concurrency (--workers) with backpressure for free — the channel
// simply blocks producers once it's full.
//
// ctx cancellation (e.g. from Ctrl+C in main.go) is checked both before
// dialing each job and is respected by net.DialTimeout's underlying
// dialer via a context-aware Dialer, so in-flight scans stop promptly
// instead of running every queued job to completion.
//
// onResult is optional (variadic so existing 5-argument call sites —
// including tests and benchmarks — keep compiling unchanged) and, if
// given, is invoked once per completed probe from the single consumer
// goroutine below, never from the worker goroutines themselves — so
// callers never need their own locking just to observe progress.
func ScanTCP(ctx context.Context, hosts []string, ports []int, workers int, timeout time.Duration, onResult ...func(PortResult)) []PortResult {
	if workers < 1 {
		workers = 1
	}
	var notify func(PortResult)
	if len(onResult) > 0 {
		notify = onResult[0]
	}

	jobs := make(chan job, workers*4) // small buffer smooths producer/consumer speed mismatches
	results := make(chan PortResult, workers*4)

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go tcpWorker(ctx, &wg, jobs, results, timeout)
	}

	// Producer: feed the job queue, but stop early if the context is
	// cancelled so we don't block forever trying to send into a channel
	// no one is receiving from anymore.
	go func() {
		defer close(jobs)
		for _, h := range hosts {
			for _, p := range ports {
				select {
				case jobs <- job{host: h, port: p}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	// Closer goroutine: once all workers finish, close results so the
	// range loop below terminates.
	go func() {
		wg.Wait()
		close(results)
	}()

	out := make([]PortResult, 0, len(hosts)*len(ports))
	for r := range results {
		out = append(out, r)
		if notify != nil {
			notify(r)
		}
	}
	return out
}

// tcpWorker pulls jobs off the channel until it's closed or ctx is
// cancelled, dialing each host:port with a bounded timeout via
// net.DialTimeout.
func tcpWorker(ctx context.Context, wg *sync.WaitGroup, jobs <-chan job, results chan<- PortResult, timeout time.Duration) {
	defer wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case j, ok := <-jobs:
			if !ok {
				return
			}
			results <- probeTCP(ctx, j.host, j.port, timeout)
		}
	}
}

// probeTCP performs a single TCP connect attempt. net.DialTimeout is
// used (rather than net.Dial + a manual timer) because it directly
// bounds the whole connect operation including DNS resolution of the
// host, which is exactly the failure mode we want to time out on when
// scanning a large target list.
//
// State classification:
//   - connection succeeds            -> StateOpen
//   - "connection refused"           -> StateClosed (target actively rejected us)
//   - timeout / no response at all   -> StateFiltered (likely a firewall dropping packets)
func probeTCP(ctx context.Context, host string, port int, timeout time.Duration) PortResult {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	start := time.Now()

	var d net.Dialer
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, err := d.DialContext(dialCtx, "tcp", addr)
	latency := time.Since(start)

	res := PortResult{Host: host, Port: port, Protocol: "tcp", Latency: latency}

	if err != nil {
		if isRefused(err) {
			res.State = StateClosed
		} else {
			res.State = StateFiltered
		}
		return res
	}
	defer conn.Close()

	res.State = StateOpen
	return res
}

// isRefused reports whether err represents an actively-refused TCP
// connection (SYN/ACK -> RST) as opposed to a timeout/no-response,
// which matters for distinguishing "closed" from "filtered" in reports.
func isRefused(err error) bool {
	var opErr *net.OpError
	if ok := asOpError(err, &opErr); !ok {
		return false
	}
	// net.OpError wraps a *os.SyscallError for connection-refused on
	// Linux; comparing the formatted message is the simplest portable
	// check available without importing syscall-specific error codes.
	return strings.Contains(opErr.Err.Error(), "refused")
}

// asOpError walks the error's Unwrap() chain looking for a *net.OpError,
// since DialContext may wrap it (e.g. inside a context deadline error).
func asOpError(err error, target **net.OpError) bool {
	for err != nil {
		if opErr, ok := err.(*net.OpError); ok {
			*target = opErr
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
