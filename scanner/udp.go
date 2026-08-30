package scanner

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// ScanUDP probes each host:port pair with a UDP packet and classifies
// the result using the SAME worker-pool shape as ScanTCP for
// consistency, but a fundamentally weaker signal underneath it.
//
// IMPORTANT LIMITATION (read before trusting these results):
// UDP is connectionless, so there is no handshake to observe. We can
// only distinguish two outcomes with any confidence:
//
//  1. We get back an ICMP "port unreachable" error on the socket
//     (surfaced by Go as a net.OpError, typically wrapping
//     "connection refused" on Linux even for UDP, because the kernel
//     translates the ICMP error onto the socket) -> the port is almost
//     certainly StateClosed.
//  2. We get no response before the timeout -> StateOpenFiltered. This
//     is genuinely ambiguous: it could mean the port is open and the
//     service simply didn't reply to our unsolicited empty/garbage
//     probe (most UDP services stay silent unless they get a
//     protocol-correct request), OR a firewall silently dropped both
//     our probe and/or the ICMP unreachable reply.
//
// We do NOT claim to distinguish open from filtered — that would
// require protocol-specific payloads for every service (DNS query for
// port 53, NTP request for port 123, etc.) which is out of scope here.
// Treat StateOpenFiltered as "needs a follow-up, protocol-aware check",
// exactly like nmap's own UDP scan documentation recommends.
//
// onResult is optional (variadic, same reasoning as ScanTCP) and is
// invoked once per completed probe from the single consumer goroutine
// below.
func ScanUDP(ctx context.Context, hosts []string, ports []int, workers int, timeout time.Duration, onResult ...func(PortResult)) []PortResult {
	if workers < 1 {
		workers = 1
	}
	var notify func(PortResult)
	if len(onResult) > 0 {
		notify = onResult[0]
	}

	jobs := make(chan job, workers*4)
	results := make(chan PortResult, workers*4)

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go udpWorker(ctx, &wg, jobs, results, timeout)
	}

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

func udpWorker(ctx context.Context, wg *sync.WaitGroup, jobs <-chan job, results chan<- PortResult, timeout time.Duration) {
	defer wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case j, ok := <-jobs:
			if !ok {
				return
			}
			results <- probeUDP(j.host, j.port, timeout)
		}
	}
}

// probeUDP sends a single empty (zero-length) UDP datagram and waits
// for either a read error (ICMP unreachable surfaced by the kernel) or
// a timeout. net.DialUDP is used instead of net.ListenUDP + WriteTo
// because Dial gives us a connected UDP socket, which is what lets the
// OS deliver an ICMP port-unreachable error back to us via Read at all
// — an unconnected socket has no association to blame the ICMP error on.
func probeUDP(host string, port int, timeout time.Duration) PortResult {
	res := PortResult{Host: host, Port: port, Protocol: "udp"}

	raddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	if err != nil {
		res.State = StateFiltered
		return res
	}

	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		res.State = StateFiltered
		return res
	}
	defer conn.Close()

	start := time.Now()
	// Empty probe payload: enough to trigger an ICMP unreachable from a
	// genuinely closed port on most stacks, without needing a
	// protocol-specific payload for every possible service.
	if _, err := conn.Write([]byte{}); err != nil {
		res.State = StateFiltered
		res.Latency = time.Since(start)
		return res
	}

	conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 512)
	_, err = conn.Read(buf)
	res.Latency = time.Since(start)

	if err == nil {
		// A service that actually replied to an empty datagram — rare,
		// but unambiguous: the port is genuinely open.
		res.State = StateOpen
		return res
	}

	if isRefused(err) {
		// ICMP port-unreachable surfaced as a connection-refused style
		// error on the connected UDP socket.
		res.State = StateClosed
		return res
	}

	// Timeout or any other read error: can't tell open from filtered.
	res.State = StateOpenFiltered
	return res
}
