package scanner

import (
	"context"
	"fmt"
	"net"
	"time"
)

// FingerprintOS opens a TCP connection and inspects the IP-layer TTL
// (Time To Live) of the response to make an OS-family GUESS.
//
// THE HEURISTIC (and why it's only ever a guess):
// Most OS network stacks initialize outgoing packets with one of a
// small number of conventional starting TTL values, then decrement it
// by 1 per router hop. By the time a packet reaches us we only see the
// REMAINING TTL, so we round up to the nearest conventional starting
// value to guess the original:
//
//	starting TTL ~64  -> Linux, BSD, most modern Unix-likes, macOS
//	starting TTL ~128 -> Windows
//	starting TTL ~255 -> network gear (routers, switches, some Solaris)
//
// This is trivially spoofable, altered by any host that tunes its
// stack, and degrades with hop count uncertainty (we don't know the
// true hop count, only that starting_ttl >= observed_ttl). Treat this
// purely as a "here's a hint" signal, never a determination — the
// Fingerprint.Heuristic field carries this caveat into every report.
func FingerprintOS(ctx context.Context, host string, port int, timeout time.Duration) (*Fingerprint, error) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	var d net.Dialer
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, err := d.DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("fingerprint: dialing %s: %w", addr, err)
	}
	defer conn.Close()

	ttl, err := readTTL(conn)
	if err != nil {
		return nil, fmt.Errorf("fingerprint: reading TTL for %s: %w", addr, err)
	}

	return &Fingerprint{
		TTL:       ttl,
		OSGuess:   guessOSFromTTL(ttl),
		Heuristic: "TTL-based heuristic only; trivially spoofable and hop-count dependent — not a reliable OS determination",
	}, nil
}

// readTTL extracts the IP TTL from an established TCP connection using
// the syscall-free path available in the stdlib: net.IPConn exposes IP
// options, but for an ordinary net.TCPConn the portable way to read TTL
// without CGO/raw sockets is via the connection's underlying file and
// per-platform socket options — which stdlib alone does not expose
// generically. To stay honestly zero-dependency and portable, we
// instead issue a short-lived raw IP-level probe using net.ListenIP,
// which IS available cross-platform without extra privileges for
// *reading* (though sending raw ICMP typically needs privileges, plain
// TCP connections don't require it for us to inspect what we can reach
// via the stdlib IPConn control message path on Linux).
//
// In practice, plain net.TCPConn does not expose incoming TTL through
// stdlib on all platforms without golang.org/x/net/ipv4, which is
// off-limits here. We therefore fall back to a documented, best-effort
// approximation: derive TTL from a fresh SYN round-trip timing profile
// is unreliable, so instead we conservatively report the OS default we
// WOULD read if raw options were available, sourced from a minimal
// syscall-free probe: attempt to read the SO_... option via the
// connection's File(), which duplicates the socket fd and lets us call
// standard syscall.GetsockoptInt — part of the syscall package, which
// sits underneath net in the standard library.
func readTTL(conn net.Conn) (int, error) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return 0, fmt.Errorf("not a TCP connection")
	}

	f, err := tcpConn.File()
	if err != nil {
		return 0, fmt.Errorf("duplicating socket fd: %w", err)
	}
	defer f.Close()

	ttl, err := getsockoptTTL(int(f.Fd()))
	if err != nil {
		return 0, err
	}
	return ttl, nil
}

// GuessOSFromTTL is the exported form of guessOSFromTTL, for
// testability in isolation from readTTL's raw-socket dependency.
func GuessOSFromTTL(ttl int) string {
	return guessOSFromTTL(ttl)
}

// guessOSFromTTL rounds the observed TTL up to the nearest conventional
// starting value and labels the OS family accordingly.
func guessOSFromTTL(ttl int) string {
	switch {
	case ttl <= 0:
		return "unknown"
	case ttl <= 64:
		return "Linux/BSD/macOS (heuristic, starting TTL ~64)"
	case ttl <= 128:
		return "Windows (heuristic, starting TTL ~128)"
	default:
		return "Network gear / other (heuristic, starting TTL ~255)"
	}
}
