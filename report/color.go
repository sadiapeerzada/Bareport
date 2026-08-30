package report

import (
	"os"

	"bareport/scanner"
)

// Raw ANSI escape codes (section 11 explicitly asks for raw codes, not
// a coloring library — keeps this zero-dependency). \033[ is ESC[, the
// Control Sequence Introducer; the trailing 'm' selects "set graphics
// mode" with the given parameter.
const (
	ansiRed    = "\033[31m"
	ansiYellow = "\033[33m"
	ansiGreen  = "\033[32m"
	ansiReset  = "\033[0m"
)

// IsTTY reports whether f is attached to a genuine terminal, so
// callers can decide whether to emit color or fire an interactive
// prompt. Two-stage check:
//  1. os.ModeCharDevice on Stat() — a fast pre-filter. Piping to a
//     file or another process yields a regular file/pipe mode, not a
//     character device, so this alone rules out the common
//     non-interactive cases cheaply.
//  2. isRealTTY (tty_linux.go / tty_darwin.go / tty_other.go) — a
//     genuine ioctl-based terminal check (TCGETS on Linux, TIOCGETA on
//     darwin), confirming the character device is actually a tty and
//     not, say, /dev/null (which is also a character device, and
//     would otherwise be a false positive — this is exactly the bug
//     this two-stage check exists to close; see tty_linux.go's doc
//     comment for the full explanation). Platforms without a real
//     isRealTTY implementation (see tty_other.go) fall back to
//     ModeCharDevice's false-positive-prone behavior.
func IsTTY(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	if info.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	return isRealTTY(f.Fd())
}

func colorizeState(s scanner.PortState) string {
	switch s {
	case scanner.StateOpen:
		return ansiGreen + string(s) + ansiReset
	case scanner.StateClosed:
		return string(s) // no color: closed is unremarkable
	default:
		return ansiYellow + string(s) + ansiReset
	}
}

func colorizeSeverity(s scanner.Severity) string {
	switch s {
	case scanner.SevCritical:
		return ansiRed + string(s) + ansiReset
	case scanner.SevWarning:
		return ansiYellow + string(s) + ansiReset
	case scanner.SevInfo:
		return ansiGreen + string(s) + ansiReset
	default:
		return "-"
	}
}
