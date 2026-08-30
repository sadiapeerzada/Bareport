package tests

import (
	"bytes"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"bareport/findings"
	"bareport/report"
	"bareport/risk"
	"bareport/scanner"
)

func sampleReport() *scanner.Report {
	r := &scanner.Report{
		StartedAt: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC),
		Duration:  2 * time.Second,
		Hosts: []scanner.HostResult{{
			Host: "127.0.0.1", Alive: true,
			Ports: []scanner.PortResult{
				{
					Host: "127.0.0.1", Port: 22, Protocol: "tcp", State: scanner.StateOpen,
					Banner: &scanner.Banner{Protocol: "ssh", Raw: "SSH-2.0-test"},
				},
				{
					Host: "127.0.0.1", Port: 443, Protocol: "tcp", State: scanner.StateOpen,
					TLS: &scanner.TLSInfo{
						Subject: "CN=localhost", Issuer: "CN=localhost",
						NotAfter: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), DaysUntilExpiry: -2000,
						SelfSigned: true,
					},
					HTTP: &scanner.HTTPInfo{
						StatusCode: 200,
						SecurityHeaders: map[string]string{
							"Strict-Transport-Security": "",
							"X-Frame-Options":           "",
							"Content-Security-Policy":   "",
							"X-Content-Type-Options":    "",
							"Referrer-Policy":           "",
						},
					},
				},
				{Host: "127.0.0.1", Port: 9999, Protocol: "tcp", State: scanner.StateClosed},
			},
		}},
	}
	r.Summarize()
	return r
}

func TestReport_WriteJSON_LoadJSON_RoundTrip(t *testing.T) {
	r := sampleReport()
	var buf bytes.Buffer
	if err := report.WriteJSON(&buf, r); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	if !strings.Contains(buf.String(), "\"hosts\"") {
		t.Error("expected JSON output to contain a hosts field")
	}

	loaded, err := report.LoadJSON(&buf)
	if err != nil {
		t.Fatalf("LoadJSON: %v", err)
	}
	if len(loaded.Hosts) != len(r.Hosts) {
		t.Errorf("expected %d hosts after round-trip, got %d", len(r.Hosts), len(loaded.Hosts))
	}
	if loaded.Summary.PortsOpen != r.Summary.PortsOpen {
		t.Errorf("expected PortsOpen=%d after round-trip, got %d", r.Summary.PortsOpen, loaded.Summary.PortsOpen)
	}
}

func TestReport_WriteCSV(t *testing.T) {
	r := sampleReport()
	var buf bytes.Buffer
	if err := report.WriteCSV(&buf, r); err != nil {
		t.Fatalf("WriteCSV: %v", err)
	}
	out := buf.String()
	if !strings.HasPrefix(out, "host,port,protocol,state") {
		t.Errorf("expected CSV header row, got: %s", out)
	}
	if !strings.Contains(out, "127.0.0.1") || !strings.Contains(out, "443") {
		t.Error("expected CSV body to contain scanned host/port data")
	}
	// 3 ports + 1 header line
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 4 {
		t.Errorf("expected 4 CSV lines (header + 3 ports), got %d: %v", len(lines), lines)
	}
}

func TestReport_WriteTable(t *testing.T) {
	r := sampleReport()
	var buf bytes.Buffer
	if err := report.WriteTable(&buf, r, false); err != nil {
		t.Fatalf("WriteTable: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "HOST") || !strings.Contains(out, "PORT") {
		t.Error("expected a table header with HOST/PORT columns")
	}
	if !strings.Contains(out, "Summary:") {
		t.Error("expected a trailing summary line")
	}
}

func TestReport_BuildAssessment(t *testing.T) {
	r := sampleReport()
	a := report.BuildAssessment(r, []string{"127.0.0.1"}, "security")

	if a.Target != "127.0.0.1" {
		t.Errorf("expected target=127.0.0.1, got %q", a.Target)
	}
	if a.Scan.Profile != "security" {
		t.Errorf("expected profile=security, got %q", a.Scan.Profile)
	}
	if len(a.Findings) == 0 {
		t.Error("expected findings to be derived from the sample report's expired self-signed cert")
	}
	if a.Risk.Score == 0 {
		t.Error("expected a non-zero risk score given the sample report's findings")
	}
	if len(a.Services) == 0 {
		t.Error("expected a non-empty service inventory from the two open ports")
	}
}

func TestReport_WriteAssessmentJSON_LoadAssessment_RoundTrip(t *testing.T) {
	r := sampleReport()
	a := report.BuildAssessment(r, []string{"127.0.0.1"}, "quick")

	var buf bytes.Buffer
	if err := report.WriteAssessmentJSON(&buf, a); err != nil {
		t.Fatalf("WriteAssessmentJSON: %v", err)
	}

	// Schema check: the new top-level keys must be present alongside
	// the original scanner.Report keys (backward compatibility).
	out := buf.String()
	for _, key := range []string{"\"target\"", "\"scan\"", "\"services\"", "\"findings\"", "\"risk\"", "\"hosts\"", "\"summary\""} {
		if !strings.Contains(out, key) {
			t.Errorf("expected JSON output to contain key %s", key)
		}
	}

	loaded, err := report.LoadAssessment(&buf)
	if err != nil {
		t.Fatalf("LoadAssessment: %v", err)
	}
	if loaded.Risk.Score != a.Risk.Score {
		t.Errorf("expected risk score %d after round-trip, got %d", a.Risk.Score, loaded.Risk.Score)
	}
	if len(loaded.Findings) != len(a.Findings) {
		t.Errorf("expected %d findings after round-trip, got %d", len(a.Findings), len(loaded.Findings))
	}
}

func TestReport_LoadAssessment_BackwardCompatible_PlainReportJSON(t *testing.T) {
	// A JSON file written by the OLD WriteJSON (bare scanner.Report,
	// no target/scan/services/findings/risk) must still load via
	// LoadAssessment without error — the whole point of embedding
	// scanner.Report rather than duplicating its fields.
	r := sampleReport()
	var buf bytes.Buffer
	if err := report.WriteJSON(&buf, r); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	a, err := report.LoadAssessment(&buf)
	if err != nil {
		t.Fatalf("LoadAssessment on a plain (old-shape) report JSON: %v", err)
	}
	if len(a.Hosts) != len(r.Hosts) {
		t.Errorf("expected %d hosts, got %d", len(r.Hosts), len(a.Hosts))
	}
	// New fields simply aren't present in the old JSON, so they should
	// be at their zero values rather than causing a decode error.
	if a.Target != "" {
		t.Errorf("expected empty Target when loading an old-shape report, got %q", a.Target)
	}
}

func TestReport_CompareAssessments_And_WriteSecurityDrift(t *testing.T) {
	before := report.BuildAssessment(sampleReport(), []string{"127.0.0.1"}, "")

	after := sampleReport()
	// Open an additional port that wasn't open before.
	after.Hosts[0].Ports = append(after.Hosts[0].Ports, scanner.PortResult{
		Host: "127.0.0.1", Port: 8080, Protocol: "tcp", State: scanner.StateOpen,
		Banner: &scanner.Banner{Protocol: "http"},
	})
	after.Summarize()
	afterAssessment := report.BuildAssessment(after, []string{"127.0.0.1"}, "")

	drift := report.CompareAssessments(before, afterAssessment)
	if !drift.HasChanges() {
		t.Fatal("expected drift.HasChanges() to be true given the newly-opened port")
	}

	foundNewPort := false
	for _, p := range drift.Ports.NewOpenPorts {
		if p.Port == 8080 {
			foundNewPort = true
		}
	}
	if !foundNewPort {
		t.Error("expected port 8080 to appear in NewOpenPorts")
	}

	var buf bytes.Buffer
	if err := report.WriteSecurityDrift(&buf, drift); err != nil {
		t.Fatalf("WriteSecurityDrift: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "SECURITY DRIFT DETECTED") {
		t.Error("expected the SECURITY DRIFT DETECTED header")
	}
	if !strings.Contains(out, "PORT 8080 opened") {
		t.Errorf("expected drift output to mention the newly-opened port, got: %s", out)
	}
}

func TestReport_CompareAssessments_NoChanges(t *testing.T) {
	a := report.BuildAssessment(sampleReport(), []string{"127.0.0.1"}, "")
	b := report.BuildAssessment(sampleReport(), []string{"127.0.0.1"}, "")

	drift := report.CompareAssessments(a, b)
	if drift.HasChanges() {
		t.Errorf("expected no drift between two scans of identical data, got: %+v", drift)
	}

	var buf bytes.Buffer
	report.WriteSecurityDrift(&buf, drift)
	if !strings.Contains(buf.String(), "No security drift detected") {
		t.Errorf("expected a 'no drift' message, got: %s", buf.String())
	}
}

func TestReport_CompareAssessments_AllDriftKinds(t *testing.T) {
	before := &report.SecurityAssessment{
		Report: *sampleReport(),
		Services: []report.ServiceSummary{
			{Host: "127.0.0.1", Port: 22, Protocol: "tcp", Service: "ssh"},
			{Host: "127.0.0.1", Port: 443, Protocol: "tcp", Service: "https"},
		},
		Findings: []findings.Finding{
			{ID: "TLS-EXPIRED-CERT", Severity: findings.SevCritical, Title: "Expired certificate", Target: "127.0.0.1", Port: 443},
			{ID: "HTTP-MISSING-HSTS", Severity: findings.SevMedium, Title: "Missing HSTS", Target: "127.0.0.1", Port: 443},
		},
		Risk: risk.Result{Score: 80, Level: "HIGH"},
	}
	before.Report.Hosts = []scanner.HostResult{{
		Host: "127.0.0.1",
		Ports: []scanner.PortResult{{
			Host: "127.0.0.1", Port: 443, Protocol: "tcp", State: scanner.StateOpen,
			TLS: &scanner.TLSInfo{Subject: "CN=old.example", NotAfter: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)},
		}},
	}}

	after := &report.SecurityAssessment{
		Report: *sampleReport(),
		Services: []report.ServiceSummary{
			{Host: "127.0.0.1", Port: 443, Protocol: "tcp", Service: "https"},
			{Host: "127.0.0.1", Port: 8080, Protocol: "tcp", Service: "http"}, // new service
		},
		Findings: []findings.Finding{
			// TLS-EXPIRED-CERT resolved (gone); HTTP-MISSING-HSTS still present; new dangerous-methods finding
			{ID: "HTTP-MISSING-HSTS", Severity: findings.SevMedium, Title: "Missing HSTS", Target: "127.0.0.1", Port: 443},
			{ID: "HTTP-DANGEROUS-METHODS", Severity: findings.SevHigh, Title: "Dangerous methods allowed", Target: "127.0.0.1", Port: 443},
		},
		Risk: risk.Result{Score: 45, Level: "MEDIUM"}, // improved: negative delta
	}
	after.Report.Hosts = []scanner.HostResult{{
		Host: "127.0.0.1",
		Ports: []scanner.PortResult{{
			Host: "127.0.0.1", Port: 443, Protocol: "tcp", State: scanner.StateOpen,
			TLS: &scanner.TLSInfo{Subject: "CN=new.example", NotAfter: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)}, // renewed cert
		}},
	}}

	drift := report.CompareAssessments(before, after)
	if !drift.HasChanges() {
		t.Fatal("expected HasChanges() to be true")
	}
	if len(drift.NewServices) != 1 || drift.NewServices[0].Port != 8080 {
		t.Errorf("expected exactly one new service on port 8080, got %+v", drift.NewServices)
	}
	if len(drift.RemovedServices) != 1 || drift.RemovedServices[0].Port != 22 {
		t.Errorf("expected exactly one removed service on port 22, got %+v", drift.RemovedServices)
	}
	if len(drift.NewFindings) != 1 || drift.NewFindings[0].ID != "HTTP-DANGEROUS-METHODS" {
		t.Errorf("expected exactly one new finding (HTTP-DANGEROUS-METHODS), got %+v", drift.NewFindings)
	}
	if len(drift.ResolvedFindings) != 1 || drift.ResolvedFindings[0].ID != "TLS-EXPIRED-CERT" {
		t.Errorf("expected exactly one resolved finding (TLS-EXPIRED-CERT), got %+v", drift.ResolvedFindings)
	}
	if len(drift.TLSCertChanges) != 1 || drift.TLSCertChanges[0].BeforeSubject != "CN=old.example" {
		t.Errorf("expected exactly one TLS cert change, got %+v", drift.TLSCertChanges)
	}
	if drift.RiskDelta != -35 {
		t.Errorf("expected RiskDelta of -35 (80 -> 45), got %d", drift.RiskDelta)
	}

	var buf bytes.Buffer
	if err := report.WriteSecurityDrift(&buf, drift); err != nil {
		t.Fatalf("WriteSecurityDrift: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"SECURITY DRIFT DETECTED",
		"+ SERVICE http detected on 127.0.0.1:8080",
		"- SERVICE ssh no longer detected on 127.0.0.1:22",
		"+ TLS certificate changed on 127.0.0.1:443",
		"+ NEW HIGH finding: Dangerous methods allowed",
		"- RESOLVED CRITICAL finding: Expired certificate",
		"Change: -35",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected WriteSecurityDrift output to contain %q, got:\n%s", want, out)
		}
	}
}

func TestReport_WriteHTML(t *testing.T) {
	a := report.BuildAssessment(sampleReport(), []string{"127.0.0.1"}, "full")
	var buf bytes.Buffer
	if err := report.WriteHTML(&buf, a); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "{{") {
		t.Error("expected no unrendered template syntax in the HTML output")
	}
	for _, want := range []string{"<html", "</html>", "Executive Summary", "Security Findings"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected HTML output to contain %q", want)
		}
	}
}

func TestReport_WriteHTML_HasDarkLightThemeToggle(t *testing.T) {
	a := report.BuildAssessment(sampleReport(), []string{"127.0.0.1"}, "full")
	var buf bytes.Buffer
	if err := report.WriteHTML(&buf, a); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	out := buf.String()

	// The dark-theme CSS variable override must exist.
	if !strings.Contains(out, `:root[data-theme="dark"]`) {
		t.Error("expected a :root[data-theme=\"dark\"] CSS block for the dark theme")
	}
	// The anti-flash script must run before first paint -- i.e. appear
	// in <head>, before the closing </head> tag, not after <body>.
	headEnd := strings.Index(out, "</head>")
	scriptIdx := strings.Index(out, "localStorage.getItem('bareport-report-theme')")
	if scriptIdx == -1 {
		t.Fatal("expected an anti-flash theme script reading the persisted theme choice")
	}
	if headEnd == -1 || scriptIdx > headEnd {
		t.Error("expected the anti-flash theme script to run in <head>, before first paint")
	}
	// The toggle button and its click handler must both be present.
	if !strings.Contains(out, `id="theme-toggle"`) {
		t.Error("expected a theme-toggle button")
	}
	if !strings.Contains(out, "getElementById('theme-toggle')") {
		t.Error("expected a click handler wired to the theme-toggle button")
	}
	// Every color used by the report must be a CSS variable (var(--x)),
	// never a hardcoded hex value outside the :root variable
	// declarations themselves -- otherwise dark mode would leave some
	// element stuck in its light-mode color.
	styleBlock := out[strings.Index(out, "<style>"):strings.Index(out, "</style>")]
	hexInStyle := regexp.MustCompile(`(?m)^[^-].*#[0-9a-fA-F]{3,6}`).FindAllString(styleBlock, -1)
	for _, line := range hexInStyle {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "--") {
			t.Errorf("found a hardcoded hex color outside a CSS variable declaration (would not respond to the theme toggle): %q", trimmed)
		}
	}
}

func TestReport_WriteHTML_WithDNSAndDedupedRemediations(t *testing.T) {
	// Exercises buildHTMLReportData's DNS branch (h.DNS != nil) and the
	// remediation-dedup path (two findings sharing one remediation
	// string should only appear once in Recommendations), neither of
	// which sampleReport()'s fixture (no DNS field, distinct
	// remediations) reaches.
	r := sampleReport()
	r.Hosts[0].DNS = &scanner.DNSInfo{
		Addresses: []string{"127.0.0.1"}, MXRecords: []string{"mail.example.com"},
		TXTRecords: []string{"v=spf1 -all"}, HasSPF: true, HasDMARC: false,
	}
	r.Summarize()
	a := report.BuildAssessment(r, []string{"127.0.0.1"}, "full")

	// Duplicate the remediation text on an extra synthetic finding to
	// exercise the "already seen this remediation" dedup branch.
	if len(a.Findings) == 0 {
		t.Fatal("expected sampleReport's fixture to already produce at least one finding")
	}
	dup := a.Findings[0]
	dup.ID = dup.ID + "-DUPLICATE"
	a.Findings = append(a.Findings, dup)

	var buf bytes.Buffer
	if err := report.WriteHTML(&buf, a); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "mail.example.com") {
		t.Error("expected the DNS MX record to appear in the HTML report")
	}
	// The shared remediation text should appear exactly once in the
	// Recommendations list, not twice, despite two findings sharing it.
	remediationCount := strings.Count(out, dup.Remediation)
	if dup.Remediation != "" && remediationCount < 1 {
		t.Errorf("expected the shared remediation text to appear at least once, got %d occurrences", remediationCount)
	}
}

func TestReport_WriteAssessmentSummary(t *testing.T) {
	a := report.BuildAssessment(sampleReport(), []string{"127.0.0.1"}, "")
	var buf bytes.Buffer
	if err := report.WriteAssessmentSummary(&buf, a, false); err != nil {
		t.Fatalf("WriteAssessmentSummary: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "BAREPORT SECURITY ASSESSMENT") {
		t.Error("expected the assessment summary box title")
	}
	if !strings.Contains(out, "Risk Score") || !strings.Contains(out, "Risk Level") {
		t.Error("expected risk score/level rows in the summary box")
	}
}

func TestReport_WriteMinimal(t *testing.T) {
	a := report.BuildAssessment(sampleReport(), []string{"127.0.0.1"}, "")
	var buf bytes.Buffer
	if err := report.WriteMinimal(&buf, a); err != nil {
		t.Fatalf("WriteMinimal: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "127.0.0.1") {
		t.Error("expected the target host in minimal output")
	}
	if !strings.Contains(out, "Risk:") || !strings.Contains(out, "Findings:") {
		t.Error("expected Risk/Findings summary lines in minimal output")
	}
	if strings.Contains(out, "9999") {
		t.Error("did not expect the closed port 9999 to appear in minimal output (open ports only)")
	}
}

func TestReport_WriteFindingExplanations(t *testing.T) {
	a := report.BuildAssessment(sampleReport(), []string{"127.0.0.1"}, "")
	var buf bytes.Buffer
	if err := report.WriteFindingExplanations(&buf, a); err != nil {
		t.Fatalf("WriteFindingExplanations: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "What:") || !strings.Contains(out, "Evidence:") || !strings.Contains(out, "Recommendation:") {
		t.Error("expected What/Evidence/Recommendation sections in the explanation output")
	}
}

func TestReport_IsTTY_FalseForNonTTY(t *testing.T) {
	// A regular *os.File pointing at a temp file (not a terminal)
	// should never report as a TTY.
	f, err := os.CreateTemp(t.TempDir(), "bareport-isatty-test")
	if err != nil {
		t.Fatalf("creating temp file: %v", err)
	}
	defer f.Close()
	if report.IsTTY(f) {
		t.Error("expected IsTTY(regular file) to be false")
	}
}

// TestReport_IsTTY_FalseForDevNull is a regression test for a real
// bug: /dev/null is a character device (like a real terminal), so a
// bare os.ModeCharDevice check alone reports a false positive for it —
// IsTTY must confirm with a genuine terminal check (isRealTTY, see
// tty_linux.go) rather than trusting the character-device bit alone.
// Before the fix, this test failed: IsTTY(/dev/null) returned true,
// which caused main.go's interactive prompt to fire on redirected
// non-interactive input like `bareport < /dev/null`.
func TestReport_IsTTY_FalseForDevNull(t *testing.T) {
	f, err := os.Open("/dev/null")
	if err != nil {
		t.Skipf("cannot open /dev/null on this platform: %v", err)
	}
	defer f.Close()
	if report.IsTTY(f) {
		t.Error("expected IsTTY(/dev/null) to be false — /dev/null is a character device but not a terminal")
	}
}

// TestReport_IsTTY_FalseForPipe covers the more common real-world
// non-interactive case (a genuine pipe, as opposed to /dev/null
// specifically) to confirm the fix didn't regress the already-working
// path — pipes were never a character device in the first place, so
// this should pass both before and after the fix, but is worth
// asserting explicitly alongside the /dev/null regression test above.
func TestReport_IsTTY_FalseForPipe(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("creating pipe: %v", err)
	}
	defer r.Close()
	defer w.Close()
	if report.IsTTY(r) {
		t.Error("expected IsTTY(pipe) to be false")
	}
}

func TestAttackSurface_OnlyOpenPortsIncluded(t *testing.T) {
	a := report.BuildAssessment(sampleReport(), []string{"127.0.0.1"}, "security")
	as := report.BuildAttackSurface(a)

	if len(as) != 1 {
		t.Fatalf("expected 1 host in attack surface, got %d", len(as))
	}
	host := as[0]
	if host.Host != "127.0.0.1" || !host.Alive {
		t.Errorf("unexpected host entry: %+v", host)
	}
	// sampleReport has ports 22 (open), 443 (open), 9999 (closed) —
	// the closed port must not appear in the attack surface at all.
	if len(host.Ports) != 2 {
		t.Fatalf("expected 2 open ports in attack surface, got %d: %+v", len(host.Ports), host.Ports)
	}
	for _, p := range host.Ports {
		if p.Port == 9999 {
			t.Error("closed port 9999 should not appear in the attack surface")
		}
	}
}

func TestAttackSurface_SeverityReflectsWorstFindingPerPort(t *testing.T) {
	a := report.BuildAssessment(sampleReport(), []string{"127.0.0.1"}, "security")
	as := report.BuildAttackSurface(a)

	var port22, port443 *report.AttackSurfacePort
	for i := range as[0].Ports {
		switch as[0].Ports[i].Port {
		case 22:
			port22 = &as[0].Ports[i]
		case 443:
			port443 = &as[0].Ports[i]
		}
	}
	if port22 == nil || port443 == nil {
		t.Fatalf("expected both port 22 and 443 in attack surface, got %+v", as[0].Ports)
	}

	// Port 22 (ssh) has no severity-bearing findings in sampleReport —
	// only the baseline NET-OPEN-PORT inventory finding every open
	// port gets (see findings/network.go), which is itself INFO
	// severity, so the worst severity for port 22 is INFO.
	if port22.Severity != string(findings.SevInfo) || port22.FindingCount != 1 {
		t.Errorf("expected port 22 to have exactly the baseline INFO open-port finding, got severity=%q count=%d", port22.Severity, port22.FindingCount)
	}
	if port22.Service != "ssh" {
		t.Errorf("expected port 22 service 'ssh', got %q", port22.Service)
	}

	// Port 443 has an expired self-signed cert (CRITICAL) plus missing
	// header findings — worst severity across all of them must be
	// CRITICAL, and FindingCount must be >1 (cert + several headers).
	if port443.Severity != string(findings.SevCritical) {
		t.Errorf("expected port 443 worst severity CRITICAL, got %q", port443.Severity)
	}
	if port443.SevClass != "sev-critical" {
		t.Errorf("expected port 443 SevClass 'sev-critical', got %q", port443.SevClass)
	}
	if port443.FindingCount < 2 {
		t.Errorf("expected port 443 to have multiple findings, got %d", port443.FindingCount)
	}
}

func TestAttackSurface_ConsistentWithOverallFindings(t *testing.T) {
	// The attack surface view must never invent or drop findings: the
	// sum of every port's FindingCount across the whole attack surface
	// must equal len(a.Findings) exactly, since every finding in
	// sampleReport carries a Target+Port that resolves to an open port.
	a := report.BuildAssessment(sampleReport(), []string{"127.0.0.1"}, "security")
	as := report.BuildAttackSurface(a)

	total := 0
	for _, h := range as {
		for _, p := range h.Ports {
			total += p.FindingCount
		}
	}
	if total != len(a.Findings) {
		t.Errorf("expected attack surface FindingCounts to sum to %d (len(a.Findings)), got %d", len(a.Findings), total)
	}
}

func TestAttackSurface_NoOpenPorts_EmptyResult(t *testing.T) {
	r := &scanner.Report{
		Hosts: []scanner.HostResult{{Host: "127.0.0.1", Alive: true, Ports: []scanner.PortResult{
			{Host: "127.0.0.1", Port: 9999, Protocol: "tcp", State: scanner.StateClosed},
		}}},
	}
	r.Summarize()
	a := report.BuildAssessment(r, []string{"127.0.0.1"}, "")
	as := report.BuildAttackSurface(a)
	if len(as) != 0 {
		t.Errorf("expected no hosts in attack surface when nothing is open, got %+v", as)
	}
}
