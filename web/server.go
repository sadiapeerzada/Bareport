// Package web implements section 14's built-in local dashboard: a
// zero-JS-framework, zero-CSS-framework HTML report viewer served by
// net/http, with templates and styles baked into the binary via
// go:embed so `--serve` works from a single compiled executable with
// no extra files to ship alongside it.
package web

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"sort"
	"time"

	"bareport/findings"
	"bareport/report"
	"bareport/risk"
	"bareport/scanner"
	"bareport/selfaudit"
)

//go:embed templates/*.html
var templatesFS embed.FS

//go:embed static/*.css
var staticFS embed.FS

// Server holds the live assessment (and, once diff mode has been used,
// the previous assessment to diff against) and serves them over HTTP.
type Server struct {
	tmpl     *template.Template
	current  *report.SecurityAssessment
	previous *report.SecurityAssessment // nil unless a diff comparison is available
}

// New parses the embedded templates and returns a Server ready to
// Serve. Parsing at construction time (rather than per-request) means a
// broken template fails fast at startup instead of mid-demo.
func New(current, previous *report.SecurityAssessment) (*Server, error) {
	tmpl, err := template.New("dashboard.html").Funcs(templateFuncs()).ParseFS(templatesFS, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("web: parsing templates: %w", err)
	}
	return &Server{tmpl: tmpl, current: current, previous: previous}, nil
}

// Serve starts the dashboard on addr (host:port; port 0 picks a free
// port) and blocks until ctx is cancelled, at which point it shuts the
// server down gracefully. It prints the resolved URL before blocking so
// `--serve` demos show a clickable link immediately.
// Handler builds the dashboard's http.Handler without binding a
// listener or blocking — exported specifically so tests can drive it
// directly via httptest.NewServer(s.Handler()) rather than needing a
// real network port and a goroutine racing Serve's own startup. Serve
// itself uses this too, so there's exactly one place the route table
// is defined.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleDashboard)
	mux.HandleFunc("/api/report.json", s.handleReportJSON)
	mux.Handle("/static/", http.FileServer(http.FS(staticFS)))
	if s.previous != nil {
		mux.HandleFunc("/diff", s.handleDiff)
	}
	return mux
}

// Serve starts the dashboard on addr (host:port; port 0 picks a free
// port) and blocks until ctx is cancelled, at which point it shuts the
// server down gracefully. It prints the resolved URL before blocking so
// `--serve` demos show a clickable link immediately.
func (s *Server) Serve(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("web: listening on %s: %w", addr, err)
	}

	srv := &http.Server{Handler: s.Handler()}
	log.Printf("bareport dashboard: http://%s/", ln.Addr().String())

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ln) }()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("web: server error: %w", err)
		}
		return nil
	}
}

// dashboardData is the exact shape the html/template file renders from.
// Kept separate from scanner.Report/SecurityAssessment so the template
// can stay simple (pre-sorted rows, pre-computed labels) rather than
// doing logic inline in template actions, which gets unreadable fast.
type dashboardData struct {
	Summary     scanner.Summary
	Duration    string
	GeneratedAt string
	Target      string
	Rows        []rowData
	HasDiff     bool

	// Risk overview + findings table — new in this round of work
	// (section 6: dashboard improvements), additive to the existing
	// port-level table above, not a replacement for it.
	Risk         riskData
	FindingRows  []findingRowData
	ServiceCount int

	// RiskBreakdown (feature #4) and ZeroDep (feature #7) — both
	// additive, both computed from real data at request time (see
	// buildDashboardData / zeroDepStatus), same as everything else on
	// this page.
	RiskBreakdown []categoryRowData
	ZeroDep       zeroDepData

	// AttackSurface (feature #5): host/port/protocol/service/finding
	// data already collected, regrouped into a host-by-open-port view
	// for the new Attack Surface section — additive alongside the
	// existing port table above, not a replacement for it.
	AttackSurface []report.AttackSurfaceHost
}

type categoryRowData struct {
	Category string
	Points   int
	Total    int
	Pct      int
}

// zeroDepData mirrors report.zeroDepView — kept as its own small type
// here rather than importing report's unexported view type, matching
// how riskData/findingRowData already re-derive their own dashboard-
// shaped views from the same underlying data rather than reusing
// report package's HTML-report-specific view types.
type zeroDepData struct {
	Verified      bool
	ImportsWalked int
	OutsideStdlib []string
}

type riskData struct {
	Score    int
	Level    string
	Critical int
	High     int
	Medium   int
	Low      int
	Info     int
}

type findingRowData struct {
	ID          string
	Severity    string
	SevClass    string // fsev-critical / fsev-high / fsev-medium / fsev-low / fsev-info
	Title       string
	Host        string
	Port        int
	Evidence    string
	Description string
	Remediation string
}

type rowData struct {
	Host        string
	Port        int
	Protocol    string
	State       string
	StateClass  string // CSS class: state-open / state-closed / state-filtered
	Service     string
	Severity    string
	SevClass    string // CSS class: sev-critical / sev-warning / sev-info / sev-none
	Findings    []scanner.Finding
	Banner      *scanner.Banner
	TLS         *scanner.TLSInfo
	HTTP        *scanner.HTTPInfo
	Fingerprint *scanner.Fingerprint
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	data := buildDashboardData(s.current)
	data.HasDiff = s.previous != nil

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.Execute(w, data); err != nil {
		http.Error(w, fmt.Sprintf("template error: %v", err), http.StatusInternalServerError)
	}
}

func (s *Server) handleReportJSON(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(s.current)
}

func (s *Server) handleDiff(w http.ResponseWriter, r *http.Request) {
	d := report.CompareAssessments(s.previous, s.current)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<pre style=\"font-family:ui-monospace,monospace;padding:2rem;\">")
	var buf []byte
	buf, _ = json.MarshalIndent(d, "", "  ")
	fmt.Fprintf(w, "%s", template.HTMLEscapeString(string(buf)))
	fmt.Fprintf(w, "</pre>")
}

// buildDashboardData flattens a SecurityAssessment into the row-per-port
// shape the template needs for the existing port table, plus a
// row-per-finding shape for the new findings table, and sorts both
// worst-first so the most important information surfaces at the top of
// the initial view — the sortable-column JS in dashboard.html lets the
// user re-sort from there.
func buildDashboardData(a *report.SecurityAssessment) dashboardData {
	r := &a.Report
	data := dashboardData{
		Summary:      r.Summary,
		Duration:     r.Duration.Round(time.Millisecond).String(),
		GeneratedAt:  r.StartedAt.Format("2006-01-02 15:04:05 MST"),
		Target:       a.Target,
		ServiceCount: len(a.Services),
		Risk: riskData{
			Score: a.Risk.Score, Level: a.Risk.Level,
			Critical: a.Risk.Counts.Critical, High: a.Risk.Counts.High,
			Medium: a.Risk.Counts.Medium, Low: a.Risk.Counts.Low, Info: a.Risk.Counts.Info,
		},
	}

	for _, h := range r.Hosts {
		for _, p := range h.Ports {
			sev, sevClass := worstSeverity(p.Findings)
			row := rowData{
				Host:        p.Host,
				Port:        p.Port,
				Protocol:    p.Protocol,
				State:       string(p.State),
				StateClass:  "state-" + stateClass(p.State),
				Service:     serviceName(p.Banner),
				Severity:    sev,
				SevClass:    sevClass,
				Findings:    p.Findings,
				Banner:      p.Banner,
				TLS:         p.TLS,
				HTTP:        p.HTTP,
				Fingerprint: p.Fingerprint,
			}
			data.Rows = append(data.Rows, row)
		}
	}
	sort.SliceStable(data.Rows, func(i, j int) bool {
		ri, rj := sevRank(data.Rows[i].SevClass), sevRank(data.Rows[j].SevClass)
		if ri != rj {
			return ri > rj
		}
		return data.Rows[i].Host < data.Rows[j].Host
	})

	for _, f := range a.Findings {
		data.FindingRows = append(data.FindingRows, findingRowData{
			ID: f.ID, Severity: string(f.Severity), SevClass: findingSevClass(f.Severity),
			Title: f.Title, Host: f.Target, Port: f.Port,
			Evidence: f.Evidence, Description: f.Description, Remediation: f.Remediation,
		})
	}
	// a.Findings is already sorted worst-first by findings.Analyze; no
	// re-sort needed here.

	data.RiskBreakdown = buildCategoryRows(a.Findings)
	data.ZeroDep = zeroDepStatus()
	data.AttackSurface = report.BuildAttackSurface(a)

	return data
}

// buildCategoryRows converts risk.Breakdown's output into
// categoryRowData, pre-computing each row's bar width the same way
// buildDashboardData already does for nothing else on this page (this
// is the first bar chart the dashboard has) — percentage of the
// largest category's points, so the biggest contributor is always a
// full-width bar.
func buildCategoryRows(fs []findings.Finding) []categoryRowData {
	bd := risk.Breakdown(fs)
	max := 0
	for _, c := range bd {
		if c.Points > max {
			max = c.Points
		}
	}
	out := make([]categoryRowData, 0, len(bd))
	for _, c := range bd {
		pct := 0
		if max > 0 {
			pct = c.Points * 100 / max
		}
		out = append(out, categoryRowData{Category: c.Category, Points: c.Points, Total: c.Counts.Total(), Pct: pct})
	}
	return out
}

// zeroDepStatus calls selfaudit.Verify() fresh on every dashboard
// request — the same function `bareport --verify-zero-dep` calls at
// the terminal (cli.go's runVerifyZeroDep) — so what the dashboard
// shows is always the real, current verification status, never a
// value baked in at build or scan time.
func zeroDepStatus() zeroDepData {
	r := selfaudit.Verify()
	return zeroDepData{Verified: r.Verified(), ImportsWalked: r.ImportsWalked, OutsideStdlib: r.OutsideStdlib}
}

func stateClass(s scanner.PortState) string {
	switch s {
	case scanner.StateOpen:
		return "open"
	case scanner.StateClosed:
		return "closed"
	default:
		return "filtered"
	}
}

func serviceName(b *scanner.Banner) string {
	if b == nil {
		return "-"
	}
	return b.Protocol
}

func worstSeverity(findings []scanner.Finding) (string, string) {
	if len(findings) == 0 {
		return "none", "sev-none"
	}
	worst := scanner.SevInfo
	for _, f := range findings {
		if sevRank(string(f.Severity)) > sevRank(string(worst)) {
			worst = f.Severity
		}
	}
	return string(worst), "sev-" + string(worst)
}

func sevRank(s string) int {
	switch s {
	case "critical", "sev-critical":
		return 3
	case "warning", "sev-warning":
		return 2
	case "info", "sev-info":
		return 1
	default:
		return 0
	}
}

// findingSevClass maps the findings package's five-tier Severity to a
// CSS class distinct from the port table's three-tier sev-* classes
// above (sev-critical/sev-warning/sev-info/sev-none), so the two
// tables' styling never collides — prefixed "fsev-" for "finding
// severity".
func findingSevClass(s findings.Severity) string {
	switch s {
	case findings.SevCritical:
		return "fsev-critical"
	case findings.SevHigh:
		return "fsev-high"
	case findings.SevMedium:
		return "fsev-medium"
	case findings.SevLow:
		return "fsev-low"
	default:
		return "fsev-info"
	}
}

func templateFuncs() template.FuncMap {
	return template.FuncMap{
		"asClass": attackSurfaceTileClass,
	}
}

// attackSurfaceTileClass maps an AttackSurfacePort.Severity string to
// its own "as-*" CSS class family (web/static/style.css), deliberately
// distinct from both the port table's three-tier sev-* classes and
// the findings table's five-tier fsev-* classes — the attack-surface
// grid renders whole colored tiles, a different visual treatment from
// either existing severity indicator, so it gets its own class
// namespace rather than overloading one of theirs.
func attackSurfaceTileClass(sev string) string {
	switch sev {
	case "CRITICAL":
		return "as-critical"
	case "HIGH":
		return "as-high"
	case "MEDIUM":
		return "as-medium"
	case "LOW":
		return "as-low"
	case "INFO":
		return "as-info"
	default:
		return "as-none"
	}
}
