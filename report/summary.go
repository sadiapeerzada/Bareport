package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"bareport/scanner"
)

// WriteAssessmentSummary renders the boxed "BAREPORT SECURITY
// ASSESSMENT" panel shown after the normal port table — the terminal
// equivalent of the HTML report's executive summary. Built with plain
// box-drawing characters via fmt, same as every other terminal
// renderer in this package (no TUI/box library).
func WriteAssessmentSummary(w io.Writer, a *SecurityAssessment, useColor bool) error {
	hostsScanned := a.Summary.HostsScanned
	openPorts := a.Summary.PortsOpen
	services := len(a.Services)
	findingCount := len(a.Findings)

	target := a.Target
	if target == "" {
		target = "-"
	}

	lines := []struct{ label, value string }{
		{"Target", target},
		{"Hosts", fmt.Sprintf("%d", hostsScanned)},
		{"Open Ports", fmt.Sprintf("%d", openPorts)},
		{"Services", fmt.Sprintf("%d", services)},
		{"Findings", fmt.Sprintf("%d", findingCount)},
		{"Risk Score", fmt.Sprintf("%d / 100", a.Risk.Score)},
		{"Risk Level", a.Risk.Level},
	}

	sevLines := []struct{ label, value string }{
		{"CRITICAL", fmt.Sprintf("%d", a.Risk.Counts.Critical)},
		{"HIGH", fmt.Sprintf("%d", a.Risk.Counts.High)},
		{"MEDIUM", fmt.Sprintf("%d", a.Risk.Counts.Medium)},
		{"LOW", fmt.Sprintf("%d", a.Risk.Counts.Low)},
		{"INFO", fmt.Sprintf("%d", a.Risk.Counts.Info)},
	}

	width := 46
	for _, l := range lines {
		if w := len(l.label) + len(l.value) + 4; w > width {
			width = w
		}
	}

	title := "BAREPORT SECURITY ASSESSMENT"
	pad := (width - len(title)) / 2
	if pad < 0 {
		pad = 0
	}

	_ = useColor // reserved: severity rows are intentionally left uncolored for now, see row()

	fmt.Fprintln(w, "╭"+strings.Repeat("─", width)+"╮")
	fmt.Fprintf(w, "│%s%s%s│\n", strings.Repeat(" ", pad), title, strings.Repeat(" ", width-pad-len(title)))
	fmt.Fprintln(w, "├"+strings.Repeat("─", width)+"┤")
	for _, l := range lines {
		row(w, width, l.label, l.value)
	}
	fmt.Fprintln(w, "├"+strings.Repeat("─", width)+"┤")
	for _, l := range sevLines {
		row(w, width, l.label, l.value)
	}
	fmt.Fprintln(w, "╰"+strings.Repeat("─", width)+"╯")

	return nil
}

func row(w io.Writer, width int, label, value string) {
	content := fmt.Sprintf(" %s:", label)
	padding := width - len(content) - len(value) - 1
	if padding < 1 {
		padding = 1
	}
	fmt.Fprintf(w, "│%s%s%s │\n", content, strings.Repeat(" ", padding), value)
}

// WriteMinimal renders the compact --minimal output: target, an
// aligned open-port list, and a one-line risk/findings summary. No
// severity/notes columns, no box drawing — just enough to answer "is
// this target okay" at a glance, e.g. for piping into another tool's
// log line.
func WriteMinimal(w io.Writer, a *SecurityAssessment) error {
	for _, h := range a.Hosts {
		fmt.Fprintln(w, h.Host)
		var open []scanner.PortResult
		for _, p := range h.Ports {
			if p.State == scanner.StateOpen {
				open = append(open, p)
			}
		}
		sort.Slice(open, func(i, j int) bool { return open[i].Port < open[j].Port })
		for _, p := range open {
			service := "unknown"
			if p.Banner != nil {
				service = p.Banner.Protocol
			}
			fmt.Fprintf(w, "%-8s %s\n", fmt.Sprintf("%d/%s", p.Port, p.Protocol), service)
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintf(w, "Risk: %s\n", a.Risk.Level)
	fmt.Fprintf(w, "Findings: %d\n", len(a.Findings))
	return nil
}

// WriteFindingExplanations renders every finding in the "[SEVERITY]
// Title / What / Evidence / Recommendation" long-form shape — the CLI
// explanation format findings are shown in via --explain. This uses
// exactly the Finding.Description/Evidence/Remediation fields the
// JSON/HTML output also carry; nothing here is generated beyond what
// findings.Analyze already produced (no AI, no network calls — see
// findings/*.go for the deterministic rules that produced this text in
// the first place).
func WriteFindingExplanations(w io.Writer, a *SecurityAssessment) error {
	if len(a.Findings) == 0 {
		fmt.Fprintln(w, "No findings.")
		return nil
	}
	for i, f := range a.Findings {
		if i > 0 {
			fmt.Fprintln(w)
		}
		fmt.Fprintf(w, "[%s] %s\n\n", f.Severity, f.Title)
		fmt.Fprintf(w, "What:\n%s\n\n", f.Description)
		fmt.Fprintf(w, "Evidence:\n%s\n", f.Evidence)
		if f.Target != "" {
			fmt.Fprintf(w, "Host: %s\n", f.Target)
		}
		if f.Port != 0 {
			fmt.Fprintf(w, "Port: %d\n", f.Port)
		}
		fmt.Fprintf(w, "\nRecommendation:\n%s\n", f.Remediation)
	}
	return nil
}
