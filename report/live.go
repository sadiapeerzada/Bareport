package report

import (
	"fmt"
	"io"
	"sync"
	"time"

	"bareport/scanner"
)

// LiveDashboard is an in-place-redrawing terminal progress display,
// built entirely from fmt + raw ANSI escape codes:
//
//	\033[2K   erase the entire current line (cursor position unchanged)
//	\033[<n>A move the cursor up n lines
//
// No external TUI library (no bubbletea, no termbox) — see STDLIB.md's
// "charmbracelet/bubbletea" entry for the explicit substitution
// rationale. The technique itself is the same one every "live progress"
// CLI tool uses under the hood: track how many lines you drew last
// time, move the cursor back up that many lines, clear and redraw each
// one. There's nothing bubbletea-specific about it; a full TUI
// framework buys you widget layout, mouse input, and alternate-screen
// management, none of which a five-line scan-progress readout needs.
//
// Redraws are driven by a time.Ticker on a fixed cadence
// (redrawInterval), decoupled from how often Update is called — Update
// itself just stores the latest snapshot behind a mutex and returns
// immediately, since it's invoked from the scan's hot path (once per
// completed port probe) and must never block on terminal I/O. This
// ticker-driven-redraw-decoupled-from-event-rate shape is exactly what
// a library like schollz/progressbar gives you; see STDLIB.md.
type LiveDashboard struct {
	w io.Writer

	mu       sync.Mutex
	snapshot scanner.ProgressSnapshot

	redrawInterval time.Duration
	lastLineCount  int

	stopCh chan struct{}
	doneCh chan struct{}
}

// NewLiveDashboard returns a dashboard that will write its in-place
// redraws to w (typically os.Stdout). It does not start redrawing
// until Start is called, so a caller can construct it, wire it as a
// scanner.ProgressFunc, and only Start it once it has decided the
// terminal actually supports this (see report.IsTTY).
func NewLiveDashboard(w io.Writer) *LiveDashboard {
	return &LiveDashboard{w: w, redrawInterval: 150 * time.Millisecond}
}

// Update records the latest progress snapshot. Safe to call from any
// goroutine (scanner.Run calls it from its single scanning goroutine),
// and safe to call at high frequency — it does no I/O itself.
func (d *LiveDashboard) Update(s scanner.ProgressSnapshot) {
	d.mu.Lock()
	d.snapshot = s
	d.mu.Unlock()
}

// Start begins redrawing at d.redrawInterval until Stop is called.
func (d *LiveDashboard) Start() {
	d.stopCh = make(chan struct{})
	d.doneCh = make(chan struct{})

	go func() {
		defer close(d.doneCh)
		ticker := time.NewTicker(d.redrawInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				d.redraw()
			case <-d.stopCh:
				d.redraw() // final draw so the last snapshot is visible
				return
			}
		}
	}()
}

// Stop halts redrawing, waits for the final redraw to finish, and
// leaves the cursor on a fresh line below the last-drawn block so
// whatever the caller prints next (the final report table) doesn't
// collide with it.
func (d *LiveDashboard) Stop() {
	if d.stopCh == nil {
		return
	}
	close(d.stopCh)
	<-d.doneCh
	fmt.Fprintln(d.w)
}

// redraw renders the current snapshot as a fixed set of lines,
// erasing and overwriting the previous draw in place rather than
// scrolling the terminal.
func (d *LiveDashboard) redraw() {
	d.mu.Lock()
	s := d.snapshot
	d.mu.Unlock()

	lines := []string{
		fmt.Sprintf("bareport scanning...  elapsed %s", s.Elapsed.Round(time.Second)),
		fmt.Sprintf("  hosts     %d/%d", s.HostsDone, s.HostsTotal),
		fmt.Sprintf("  ports     %d/%d", s.PortsDone, s.PortsTotal),
		fmt.Sprintf("  findings  %d warning(s), %d critical(s)", s.Warnings, s.Criticals),
	}

	if d.lastLineCount > 0 {
		fmt.Fprintf(d.w, "\033[%dA", d.lastLineCount) // cursor up N lines
	}
	for _, line := range lines {
		fmt.Fprintf(d.w, "\033[2K%s\n", line) // erase line, print, newline
	}
	d.lastLineCount = len(lines)
}
