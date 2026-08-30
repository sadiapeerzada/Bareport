//go:build !linux

package scanner

import "fmt"

// getsockoptTTL: on non-Linux platforms, reading IP_TTL from an
// established TCP socket via syscall requires OS-specific option
// constants and framing this repo doesn't implement (kept out of scope
// for the practice build). Callers see a clear error and the rest of
// the scan proceeds without a fingerprint for that host, rather than
// failing the whole run.
func getsockoptTTL(fd int) (int, error) {
	return 0, fmt.Errorf("TTL fingerprinting not implemented on this platform")
}
