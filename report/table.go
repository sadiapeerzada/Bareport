// Package report renders a scanner.Report in the output formats
// section 9 asks for (table/JSON/CSV) plus the diff mode from section
// 12. Each file here is a pure function of a Report -> bytes/string;
// none of them know how the scan was performed, keeping report
// deliberately decoupled from scanner.
package report

import (
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"bareport/scanner"
)

// WriteTable renders r as a human-readable aligned table using
// text/tabwriter — the stdlib package purpose-built for exactly this:
// column alignment without manually computing padding widths, driven
// by tab-separated input and a configurable minimum column width.
func WriteTable(w io.Writer, r *scanner.Report, useColor bool) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)

	fmt.Fprintln(tw, "HOST\tPORT\tPROTO\tSTATE\tSERVICE\tSEVERITY\tNOTES")
	for _, h := range r.Hosts {
		if len(h.Ports) == 0 {
			fmt.Fprintf(tw, "%s\t-\t-\t%s\t-\t-\t-\n", h.Host, aliveLabel(h.Alive))
			continue
		}
		for _, p := range h.Ports {
			service := "-"
			if p.Banner != nil {
				service = p.Banner.Protocol
			}
			sev, notes := worstFinding(p.Findings)
			state := string(p.State)
			sevDisplay := string(sev)
			if sevDisplay == "" {
				sevDisplay = "-"
			}
			if useColor {
				state = colorizeState(p.State)
				sevDisplay = colorizeSeverity(sev)
			}
			fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%s\t%s\t%s\n",
				p.Host, p.Port, p.Protocol, state, service, sevDisplay, notes)
		}
	}
	if err := tw.Flush(); err != nil {
		return fmt.Errorf("report: flushing table: %w", err)
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, summaryLine(r, useColor))
	return nil
}

// worstFinding picks the highest-severity finding on a port (critical
// > warning > info) so the single-line table row has something
// meaningful in NOTES without dumping every finding inline; --json/--csv
// carry the full list for anyone who needs it.
func worstFinding(findings []scanner.Finding) (scanner.Severity, string) {
	if len(findings) == 0 {
		return "", "-"
	}
	best := findings[0]
	for _, f := range findings[1:] {
		if rank(f.Severity) > rank(best.Severity) {
			best = f
		}
	}
	note := best.Message
	if len(findings) > 1 {
		note = fmt.Sprintf("%s (+%d more)", note, len(findings)-1)
	}
	return best.Severity, note
}

func rank(s scanner.Severity) int {
	switch s {
	case scanner.SevCritical:
		return 3
	case scanner.SevWarning:
		return 2
	case scanner.SevInfo:
		return 1
	default:
		return 0
	}
}

func aliveLabel(alive bool) string {
	if alive {
		return "up (no open ports found)"
	}
	return "down/unreachable"
}

func summaryLine(r *scanner.Report, useColor bool) string {
	s := r.Summary
	line := fmt.Sprintf(
		"Summary: %d host(s) scanned, %d alive, %d port(s) open, %d warning(s), %d critical(s) — duration %s",
		s.HostsScanned, s.HostsAlive, s.PortsOpen, s.Warnings, s.Criticals, r.Duration.Round(time.Millisecond),
	)
	if useColor && s.Criticals > 0 {
		return ansiRed + line + ansiReset
	}
	if useColor && s.Warnings > 0 {
		return ansiYellow + line + ansiReset
	}
	if useColor {
		return ansiGreen + line + ansiReset
	}
	return line
}
