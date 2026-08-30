package report

import (
	"embed"
	"fmt"
	"html/template"
	"io"
	"sort"
	"time"

	"bareport/findings"
	"bareport/risk"
	"bareport/scanner"
	"bareport/selfaudit"
)

//go:embed html_templates/report.html
var htmlReportFS embed.FS

// htmlReportData is the exact shape html_templates/report.html renders
// from — pre-sorted, pre-labeled, so the template stays free of logic
// (same design choice as web/server.go's dashboardData).
type htmlReportData struct {
	Title       string
	GeneratedAt string
	Target      string
	Profile     string
	Duration    string

	Summary scanner.Summary
	Risk    assessmentRiskView

	RiskBreakdown []categoryBreakdownView

	Findings     []findingView
	Services     []ServiceSummary
	Hosts        []hostView
	TLSFindings  []findingView
	HTTPFindings []findingView
	DNSFindings  []dnsView

	Recommendations []string

	ZeroDep       zeroDepView
	AttackSurface []AttackSurfaceHost
}

// categoryBreakdownView is risk.CategoryBreakdown with a pre-computed
// bar-width percentage, same pattern as assessmentRiskView's *Pct
// fields — the template does pure display, no arithmetic.
type categoryBreakdownView struct {
	Category string
	Points   int
	Total    int
	Pct      int
}

// zeroDepView surfaces the real, freshly-computed selfaudit.Verify()
// result (see selfaudit.go) in the HTML report — feature #7. Nothing
// here is hardcoded: Verified/ImportsWalked/OutsideStdlib come
// straight from calling Verify() at report-render time, the same
// function `bareport --verify-zero-dep` calls at the terminal.
type zeroDepView struct {
	Verified      bool
	ImportsWalked int
	OutsideStdlib []string
}

type assessmentRiskView struct {
	Score    int
	Level    string
	Critical int
	High     int
	Medium   int
	Low      int
	Info     int
	// Pct fields are pre-computed 0-100 bar widths for the severity
	// distribution chart, so the template does pure display with no
	// division/arithmetic template actions.
	CriticalPct int
	HighPct     int
	MediumPct   int
	LowPct      int
	InfoPct     int
}

type findingView struct {
	ID          string
	Severity    string
	SevClass    string
	Title       string
	Description string
	Evidence    string
	Target      string
	Port        int
	Remediation string
}

type hostView struct {
	Host  string
	Alive bool
	Ports []scanner.PortResult
}

type dnsView struct {
	Host       string
	Addresses  []string
	MXRecords  []string
	TXTRecords []string
	HasSPF     bool
	HasDMARC   bool
}

// WriteHTML renders a self-contained HTML security report for a to w.
// "Self-contained" means exactly that: the template
// (html_templates/report.html) has all CSS inlined in a <style> block
// and, where any script is needed, plain vanilla JS inlined in a
// <script> block — no external stylesheet, font, CDN script, or
// framework of any kind, and no network fetch of any resource. Opening
// the resulting file offline in a browser renders identically to
// opening it online, because there is nothing to fetch either way.
func WriteHTML(w io.Writer, a *SecurityAssessment) error {
	tmpl, err := template.New("report.html").Funcs(template.FuncMap{
		"sevClass": sevClass,
	}).ParseFS(htmlReportFS, "html_templates/report.html")
	if err != nil {
		return fmt.Errorf("report: parsing HTML template: %w", err)
	}

	data := buildHTMLReportData(a)

	if err := tmpl.Execute(w, data); err != nil {
		return fmt.Errorf("report: rendering HTML report: %w", err)
	}
	return nil
}

func buildHTMLReportData(a *SecurityAssessment) htmlReportData {
	data := htmlReportData{
		Title:       "Bareport Security Assessment",
		GeneratedAt: time.Now().Format("2006-01-02 15:04:05 MST"),
		Target:      a.Target,
		Profile:     a.Scan.Profile,
		Duration:    a.Duration.Round(time.Millisecond).String(),
		Summary:     a.Summary,
		Risk:        riskView(a.Risk),
		Services:    a.Services,
		ZeroDep:     zeroDepStatus(),
	}

	data.RiskBreakdown = breakdownView(a.Findings)
	data.AttackSurface = BuildAttackSurface(a)

	remSet := map[string]bool{}
	for _, f := range a.Findings {
		fv := findingView{
			ID: f.ID, Severity: string(f.Severity), SevClass: sevClass(string(f.Severity)),
			Title: f.Title, Description: f.Description, Evidence: f.Evidence,
			Target: f.Target, Port: f.Port, Remediation: f.Remediation,
		}
		data.Findings = append(data.Findings, fv)

		switch {
		case len(f.ID) >= 3 && f.ID[:3] == "TLS":
			data.TLSFindings = append(data.TLSFindings, fv)
		case len(f.ID) >= 4 && f.ID[:4] == "HTTP":
			data.HTTPFindings = append(data.HTTPFindings, fv)
		}

		if f.Remediation != "" && !remSet[f.Remediation] {
			remSet[f.Remediation] = true
			data.Recommendations = append(data.Recommendations, f.Remediation)
		}
	}
	sort.Strings(data.Recommendations)

	for _, h := range a.Hosts {
		data.Hosts = append(data.Hosts, hostView{Host: h.Host, Alive: h.Alive, Ports: h.Ports})
		if h.DNS != nil {
			data.DNSFindings = append(data.DNSFindings, dnsView{
				Host: h.Host, Addresses: h.DNS.Addresses, MXRecords: h.DNS.MXRecords,
				TXTRecords: h.DNS.TXTRecords, HasSPF: h.DNS.HasSPF, HasDMARC: h.DNS.HasDMARC,
			})
		}
	}

	return data
}

// zeroDepStatus calls selfaudit.Verify() fresh, for real, at render
// time — the exact function `bareport --verify-zero-dep` calls at the
// terminal (see cli.go's runVerifyZeroDep). Nothing about this is
// hardcoded or cached from build time; a report generated by a build
// that genuinely picked up a third-party import would show that here.
func zeroDepStatus() zeroDepView {
	r := selfaudit.Verify()
	return zeroDepView{
		Verified:      r.Verified(),
		ImportsWalked: r.ImportsWalked,
		OutsideStdlib: r.OutsideStdlib,
	}
}

// breakdownView converts risk.Breakdown's output into
// categoryBreakdownView, pre-computing each category's bar width as a
// percentage of the largest category's points — same technique
// riskView already uses for the severity distribution chart above.
func breakdownView(fs []findings.Finding) []categoryBreakdownView {
	bd := risk.Breakdown(fs)
	max := 0
	for _, c := range bd {
		if c.Points > max {
			max = c.Points
		}
	}
	out := make([]categoryBreakdownView, 0, len(bd))
	for _, c := range bd {
		pct := 0
		if max > 0 {
			pct = c.Points * 100 / max
		}
		out = append(out, categoryBreakdownView{
			Category: c.Category, Points: c.Points, Total: c.Counts.Total(), Pct: pct,
		})
	}
	return out
}

func sevClass(sev string) string {
	switch sev {
	case "CRITICAL":
		return "sev-critical"
	case "HIGH":
		return "sev-high"
	case "MEDIUM":
		return "sev-medium"
	case "LOW":
		return "sev-low"
	default:
		return "sev-info"
	}
}

// riskView converts a risk.Result into the template-ready
// assessmentRiskView, pre-computing each severity's bar width as a
// percentage of the largest count (so the tallest bar is always full
// width, making relative proportions readable regardless of the
// absolute numbers involved).
func riskView(r risk.Result) assessmentRiskView {
	c := r.Counts
	max := c.Critical
	for _, v := range []int{c.High, c.Medium, c.Low, c.Info} {
		if v > max {
			max = v
		}
	}
	pct := func(v int) int {
		if max == 0 {
			return 0
		}
		return v * 100 / max
	}
	return assessmentRiskView{
		Score: r.Score, Level: r.Level,
		Critical: c.Critical, High: c.High, Medium: c.Medium, Low: c.Low, Info: c.Info,
		CriticalPct: pct(c.Critical), HighPct: pct(c.High), MediumPct: pct(c.Medium),
		LowPct: pct(c.Low), InfoPct: pct(c.Info),
	}
}
