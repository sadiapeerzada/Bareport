//go:build linux

package scanner

import "syscall"

// getsockoptTTL reads the IP_TTL socket option on Linux via the
// syscall package (standard library — it's the low-level layer that
// net itself is built on, just not usually reached for directly).
// This is the only portable-without-third-party-deps way to read the
// TTL Go actually saw on the wire for a connected TCP socket, since
// net.TCPConn doesn't surface it through its public API.
func getsockoptTTL(fd int) (int, error) {
	ttl, err := syscall.GetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_TTL)
	if err != nil {
		return 0, err
	}
	return ttl, nil
}
