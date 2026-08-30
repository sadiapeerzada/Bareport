package tests

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"bareport/report"
	"bareport/scanner"
	"bareport/web"
)

func scannerPortResultOpenHTTP(port int) scanner.PortResult {
	return scanner.PortResult{
		Host: "127.0.0.1", Port: port, Protocol: "tcp", State: scanner.StateOpen,
		Banner: &scanner.Banner{Protocol: "http"},
	}
}

func TestWeb_Dashboard_RendersRiskAndFindings(t *testing.T) {
	// Note on scope: server.go's findings/ports tables are sorted and
	// filtered entirely client-side (inline vanilla JS in
	// dashboard.html — see wireTable() there), not via server-side
	// query parameters. There is no ?sort=/?filter= handling in
	// server.go to unit-test; the server's job is just to hand back
	// correctly-populated, correctly-classed HTML rows, which is what
	// this test (and the fsev-critical assertion below) actually
	// verifies. The client-side JS itself is syntax-checked separately
	// (see the project's manual verification notes) since Go's test
	// tooling has no JS runtime to execute it against.
	a := report.BuildAssessment(sampleReport(), []string{"127.0.0.1"}, "security")

	srv, err := web.New(a, nil)
	if err != nil {
		t.Fatalf("web.New: %v", err)
	}

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	html := string(body)

	if strings.Contains(html, "{{") {
		t.Error("expected no unrendered template syntax in dashboard HTML")
	}
	for _, want := range []string{"Risk Overview", "Security Findings", "127.0.0.1"} {
		if !strings.Contains(html, want) {
			t.Errorf("expected dashboard HTML to contain %q", want)
		}
	}
	// The sample report's expired self-signed cert should have
	// produced at least one CRITICAL-severity dot class in the render.
	if !strings.Contains(html, "fsev-critical") {
		t.Error("expected at least one fsev-critical finding row")
	}
}

func TestWeb_Dashboard_404ForUnknownPath(t *testing.T) {
	a := report.BuildAssessment(sampleReport(), []string{"127.0.0.1"}, "")
	srv, err := web.New(a, nil)
	if err != nil {
		t.Fatalf("web.New: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/nonexistent")
	if err != nil {
		t.Fatalf("GET /nonexistent: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 for unknown path, got %d", resp.StatusCode)
	}
}

func TestWeb_ReportJSON_Endpoint(t *testing.T) {
	a := report.BuildAssessment(sampleReport(), []string{"127.0.0.1"}, "")
	srv, err := web.New(a, nil)
	if err != nil {
		t.Fatalf("web.New: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/report.json")
	if err != nil {
		t.Fatalf("GET /api/report.json: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "\"risk\"") {
		t.Error("expected the JSON API response to include a risk field")
	}
}

func TestWeb_StaticCSS_Served(t *testing.T) {
	a := report.BuildAssessment(sampleReport(), []string{"127.0.0.1"}, "")
	srv, err := web.New(a, nil)
	if err != nil {
		t.Fatalf("web.New: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/static/style.css")
	if err != nil {
		t.Fatalf("GET /static/style.css: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestWeb_NoDiffRouteWithoutPrevious(t *testing.T) {
	a := report.BuildAssessment(sampleReport(), []string{"127.0.0.1"}, "")
	srv, err := web.New(a, nil) // no previous assessment
	if err != nil {
		t.Fatalf("web.New: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/diff")
	if err != nil {
		t.Fatalf("GET /diff: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 for /diff with no previous assessment, got %d", resp.StatusCode)
	}
}

func TestWeb_DiffRoute_WithPrevious(t *testing.T) {
	before := report.BuildAssessment(sampleReport(), []string{"127.0.0.1"}, "")

	afterReport := sampleReport()
	afterReport.Hosts[0].Ports = append(afterReport.Hosts[0].Ports, scannerPortResultOpenHTTP(8080))
	afterReport.Summarize()
	after := report.BuildAssessment(afterReport, []string{"127.0.0.1"}, "")

	srv, err := web.New(after, before)
	if err != nil {
		t.Fatalf("web.New: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// The dashboard's own front page should now advertise a diff link.
	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "/diff") {
		t.Error("expected the dashboard to link to /diff when a previous assessment is set")
	}

	diffResp, err := http.Get(ts.URL + "/diff")
	if err != nil {
		t.Fatalf("GET /diff: %v", err)
	}
	defer diffResp.Body.Close()
	if diffResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for /diff, got %d", diffResp.StatusCode)
	}
	diffBody, _ := io.ReadAll(diffResp.Body)
	if !strings.Contains(string(diffBody), "8080") {
		t.Error("expected the diff output to mention the newly-opened port 8080")
	}
}

func TestWeb_Serve_StartsAndShutsDownCleanlyOnContextCancel(t *testing.T) {
	a := report.BuildAssessment(sampleReport(), []string{"127.0.0.1"}, "security")
	srv, err := web.New(a, nil)
	if err != nil {
		t.Fatalf("web.New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ctx, "127.0.0.1:0") }()

	// Give Serve a moment to actually bind before cancelling; there's
	// no signal back for "listening now" (Serve intentionally has no
	// separate readiness hook — see Handler()'s doc comment on why
	// tests generally prefer that route instead), so a short sleep is
	// the simplest way to avoid cancelling before Listen even runs.
	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("expected a clean shutdown (nil error) on context cancellation, got: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not return within 3s of context cancellation")
	}
}

func TestWeb_Serve_ListenFailure_ReturnsError(t *testing.T) {
	// Bind a port ourselves first so Serve's own net.Listen fails.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	addr := ln.Addr().String()

	a := report.BuildAssessment(sampleReport(), []string{"127.0.0.1"}, "security")
	srv, err := web.New(a, nil)
	if err != nil {
		t.Fatalf("web.New: %v", err)
	}

	if err := srv.Serve(context.Background(), addr); err == nil {
		t.Error("expected Serve to fail when the address is already in use")
	}
}

func TestWeb_Dashboard_RendersRiskBreakdown(t *testing.T) {
	a := report.BuildAssessment(sampleReport(), []string{"127.0.0.1"}, "security")
	srv, err := web.New(a, nil)
	if err != nil {
		t.Fatalf("web.New: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	html := string(body)

	if strings.Contains(html, "{{") {
		t.Error("expected no unrendered template syntax in dashboard HTML")
	}
	if !strings.Contains(html, "Risk Score Breakdown") {
		t.Error("expected the dashboard to render a Risk Score Breakdown section")
	}
	// sampleReport's expired self-signed cert produces TLS findings, so
	// the TLS category should show up in the rendered breakdown.
	if !strings.Contains(html, "breakdown-cat\">TLS<") {
		t.Error("expected a TLS row in the rendered risk breakdown")
	}
}

func TestWeb_Dashboard_RendersZeroDepBadge(t *testing.T) {
	a := report.BuildAssessment(sampleReport(), []string{"127.0.0.1"}, "security")
	srv, err := web.New(a, nil)
	if err != nil {
		t.Fatalf("web.New: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	html := string(body)

	if !strings.Contains(html, "Zero-dependency self-audit") {
		t.Error("expected the dashboard to render a zero-dependency self-audit badge")
	}
	// bareport's own test binary is itself zero-dependency (the whole
	// point of --verify-zero-dep), so this should render VERIFIED —
	// a real result from a real selfaudit.Verify() call, not a fixture.
	if !strings.Contains(html, "VERIFIED") {
		t.Error("expected the zero-dependency badge to render VERIFIED")
	}
}

func TestWeb_Dashboard_FindingsSeverityFilter_ChipsMatchRowClasses(t *testing.T) {
	// The Security Findings severity filter (dashboard.html's inline
	// wireTable(), configured with filterGroup:"finding" and
	// sevKey:"fsev") runs entirely client-side: it hides/shows each
	// finding row by comparing the row's data-fsev attribute against
	// the clicked chip's data-filter value. Go's test tooling can't
	// execute that inline JS, but it can verify the contract the JS
	// depends on - that the server renders exactly the fsev-* chips
	// the filter expects, and that every finding row actually carries
	// one of those same classes. If either side drifts (e.g. a
	// renamed severity class), the filter buttons would silently stop
	// matching any rows even though the JS itself is unchanged.
	a := report.BuildAssessment(sampleReport(), []string{"127.0.0.1"}, "security")
	srv, err := web.New(a, nil)
	if err != nil {
		t.Fatalf("web.New: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	html := string(body)

	wantChips := []string{
		`data-filter-group="finding" data-filter="all"`,
		`data-filter-group="finding" data-filter="fsev-critical"`,
		`data-filter-group="finding" data-filter="fsev-high"`,
		`data-filter-group="finding" data-filter="fsev-medium"`,
		`data-filter-group="finding" data-filter="fsev-low"`,
		`data-filter-group="finding" data-filter="fsev-info"`,
	}
	for _, want := range wantChips {
		if !strings.Contains(html, want) {
			t.Errorf("expected the findings filterbar to contain chip %q", want)
		}
	}

	// sampleReport()'s expired self-signed cert plus its missing HTTP
	// security headers should produce findings spanning at least the
	// critical and medium tiers, so this also confirms real rendered
	// rows (not just the chips) carry the fsev-* classes the chips
	// expect to match against.
	rowSevs := regexp.MustCompile(`data-fsev="(fsev-[a-z]+)"`).FindAllStringSubmatch(html, -1)
	if len(rowSevs) == 0 {
		t.Fatal("expected at least one rendered finding row with a data-fsev attribute")
	}
	validSev := map[string]bool{
		"fsev-critical": true, "fsev-high": true, "fsev-medium": true,
		"fsev-low": true, "fsev-info": true,
	}
	seenCritical := false
	for _, m := range rowSevs {
		sev := m[1]
		if !validSev[sev] {
			t.Errorf("finding row has data-fsev=%q, which no filter chip matches", sev)
		}
		if sev == "fsev-critical" {
			seenCritical = true
		}
	}
	if !seenCritical {
		t.Error("expected at least one fsev-critical finding row in the sample report")
	}
}

func TestWeb_StaticCSS_FindingsSeverityDotHasLabelSpacing(t *testing.T) {
	// Regression guard for the severity-dot/label spacing fix: the
	// findings table's colored indicator (.fdot) sits directly next
	// to its severity text with no flex gap on the containing <td>
	// (unlike .sc / .live-feed-row, which already space themselves
	// via flexbox), so it needs its own margin - mirroring the
	// open-ports table's equivalent ".dot" indicator, which already
	// had this spacing.
	a := report.BuildAssessment(sampleReport(), []string{"127.0.0.1"}, "")
	srv, err := web.New(a, nil)
	if err != nil {
		t.Fatalf("web.New: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/static/style.css")
	if err != nil {
		t.Fatalf("GET /static/style.css: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	css := string(body)

	rule := regexp.MustCompile(`#findings-table\s+\.fdot\s*\{[^}]*margin-right\s*:[^;]+;`)
	if !rule.MatchString(css) {
		t.Error("expected style.css to give #findings-table .fdot a margin-right rule spacing it from its label")
	}
}
