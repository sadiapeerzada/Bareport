package scanner

import (
	"context"
	"sync"
	"time"
)

// discoveryPorts is a small set of ports likely to be open on a live
// general-purpose host. We only need ONE of these to answer to declare
// the host "alive" — we're not port-scanning here, just checking for a
// pulse.
var discoveryPorts = []int{80, 443, 22, 445, 3389}

// WHY TCP-CONNECT INSTEAD OF ICMP PING:
// A "real" ping sends a raw ICMP echo request, but building raw ICMP
// packets requires either CGO + libpcap-style raw sockets or elevated
// (CAP_NET_RAW / root) privileges on most OSes — and Go's stdlib
// deliberately does not expose a portable, unprivileged raw-socket API
// (net.IPConn with ICMP needs root on Linux, or golang.org/x/net/icmp,
// which is a non-stdlib module we're forbidden from using here).
// A fast TCP connect attempt against a handful of commonly-open ports
// is a well-established, zero-privilege substitute: if ANY of them
// completes (or is actively refused, meaning something answered), the
// host has a live IP stack and we count it as up. This has known false
// negatives (a host with every discovery port firewalled looks "dead")
// so --skip-discovery lets a user bypass the check entirely.

// IsAlive checks a single host for liveness by racing short-timeout TCP
// connect attempts against discoveryPorts and returning true as soon as
// any of them either connects OR is actively refused (both prove the
// host answered at the network layer; only a timeout/no-response counts
// against it).
func IsAlive(ctx context.Context, host string, timeout time.Duration) bool {
	type probeResult struct {
		answered bool
	}
	results := make(chan probeResult, len(discoveryPorts))

	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var wg sync.WaitGroup
	for _, p := range discoveryPorts {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			r := probeTCP(probeCtx, host, port, timeout)
			answered := r.State == StateOpen || r.State == StateClosed
			select {
			case results <- probeResult{answered: answered}:
			case <-probeCtx.Done():
			}
		}(p)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	for r := range results {
		if r.answered {
			cancel() // stop remaining in-flight probes once we have our answer
			return true
		}
	}
	return false
}

// DiscoverHosts filters `hosts` down to only those that respond to
// IsAlive, running the checks concurrently (bounded by `workers`) since
// a discovery pass over a large CIDR block is itself an all-pairs
// operation worth parallelizing just like the port scan.
func DiscoverHosts(ctx context.Context, hosts []string, workers int, timeout time.Duration) map[string]bool {
	if workers < 1 {
		workers = 1
	}

	type task struct{ host string }
	tasks := make(chan task, workers*4)
	alive := make(map[string]bool, len(hosts))
	var mu sync.Mutex

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range tasks {
				up := IsAlive(ctx, t.host, timeout)
				mu.Lock()
				alive[t.host] = up
				mu.Unlock()
			}
		}()
	}

	for _, h := range hosts {
		tasks <- task{host: h}
	}
	close(tasks)
	wg.Wait()

	return alive
}
