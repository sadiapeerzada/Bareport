//go:build linux

package report

import (
	"syscall"
	"unsafe"
)

// isRealTTY performs a genuine terminal check via the TCGETS ioctl —
// the same technique golang.org/x/term uses internally (see its
// isTerminal implementation), reimplemented here with only the stdlib
// syscall and unsafe packages so bareport stays zero-dependency.
//
// Why this is needed on top of the os.ModeCharDevice check in IsTTY
// (color.go): ModeCharDevice is true for ANY character-special device
// file, not just terminals — /dev/null is a character device too, so
// a bare ModeCharDevice check reports a false positive for it. TCGETS
// only succeeds (errno 0) when fd genuinely refers to a terminal
// device; it fails with ENOTTY for /dev/null and any other non-tty
// character device, which is exactly the distinction ModeCharDevice
// alone can't make.
func isRealTTY(fd uintptr) bool {
	var termios syscall.Termios
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TCGETS, uintptr(unsafe.Pointer(&termios)))
	return errno == 0
}
