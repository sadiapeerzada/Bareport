//go:build !linux && !darwin

package report

// isRealTTY on platforms other than Linux and darwin (notably
// Windows) is not implemented — the TCGETS/TIOCGETA ioctls used in
// tty_linux.go/tty_darwin.go are POSIX-specific; Windows has no
// ioctl-based terminal check at all (it uses a console-mode API
// instead). This project is developed and tested on Linux and darwin,
// so rather than ship an unverified implementation for a platform
// it's never been run on, this fallback returns true unconditionally
// — meaning IsTTY (see color.go) falls back to its ORIGINAL
// os.ModeCharDevice-only behavior here, /dev/null false-positive
// included. See README's Limitations section for this disclosed gap.
func isRealTTY(fd uintptr) bool {
	return true
}
