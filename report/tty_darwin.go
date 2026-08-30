//go:build darwin

package report

import (
	"syscall"
	"unsafe"
)

// isRealTTY performs a genuine terminal check via the TIOCGETA ioctl —
// darwin's equivalent of Linux's TCGETS (see tty_linux.go's doc
// comment for the full rationale: os.ModeCharDevice alone can't tell
// a real terminal apart from /dev/null, since both are character
// devices). This is the same technique golang.org/x/term and the
// widely-used mattn/go-isatty package use on darwin/BSD, reimplemented
// here with only the stdlib syscall and unsafe packages so bareport
// stays zero-dependency. TIOCGETA only succeeds (errno 0) when fd
// genuinely refers to a terminal device; it fails with ENOTTY for
// /dev/null and any other non-tty character device.
func isRealTTY(fd uintptr) bool {
	var termios syscall.Termios
	_, _, errno := syscall.Syscall6(syscall.SYS_IOCTL, fd, syscall.TIOCGETA, uintptr(unsafe.Pointer(&termios)), 0, 0, 0)
	return errno == 0
}
