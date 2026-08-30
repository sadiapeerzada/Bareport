package web

// stateClass, worstSeverity, sevRank, and findingSevClass are small
// unexported pure functions with no HTTP/template dependency of their
// own. tests/web_test.go already exercises the dashboard end-to-end
// through a real httptest server, but only for the specific
// port-state/severity shapes that fixture happens to contain. These
// direct, in-package tests cover every branch (each PortState, every
// tiered severity name including "sev-" prefixed forms, and the
// five-tier findings.Severity mapping) without needing an HTTP round
// trip per case.

import (
	"testing"

	"bareport/findings"
	"bareport/scanner"
)

func TestStateClass_AllBranches(t *testing.T) {
	cases := []struct {
		state scanner.PortState
		want  string
	}{
		{scanner.StateOpen, "open"},
		{scanner.StateClosed, "closed"},
		{scanner.StateFiltered, "filtered"},
		{scanner.StateOpenFiltered, "filtered"},
	}
	for _, c := range cases {
		if got := stateClass(c.state); got != c.want {
			t.Errorf("stateClass(%q) = %q, want %q", c.state, got, c.want)
		}
	}
}

func TestServiceName_NilAndPresentBanner(t *testing.T) {
	if got := serviceName(nil); got != "-" {
		t.Errorf("serviceName(nil) = %q, want \"-\"", got)
	}
	if got := serviceName(&scanner.Banner{Protocol: "ssh"}); got != "ssh" {
		t.Errorf("serviceName(ssh banner) = %q, want \"ssh\"", got)
	}
}

func TestWorstSeverity_NoFindings(t *testing.T) {
	label, class := worstSeverity(nil)
	if label != "none" || class != "sev-none" {
		t.Errorf("worstSeverity(nil) = (%q, %q), want (\"none\", \"sev-none\")", label, class)
	}
}

func TestWorstSeverity_PicksHighestAcrossMixedSeverities(t *testing.T) {
	label, class := worstSeverity([]scanner.Finding{
		{Severity: scanner.SevInfo},
		{Severity: scanner.SevCritical},
		{Severity: scanner.SevWarning},
	})
	if label != string(scanner.SevCritical) {
		t.Errorf("worstSeverity label = %q, want %q", label, scanner.SevCritical)
	}
	if class != "sev-critical" {
		t.Errorf("worstSeverity class = %q, want %q", class, "sev-critical")
	}
}

func TestSevRank_AllNamedFormsAndDefault(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"critical", 3}, {"sev-critical", 3},
		{"warning", 2}, {"sev-warning", 2},
		{"info", 1}, {"sev-info", 1},
		{"none", 0}, {"sev-none", 0}, {"bogus", 0}, {"", 0},
	}
	for _, c := range cases {
		if got := sevRank(c.in); got != c.want {
			t.Errorf("sevRank(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestFindingSevClass_AllFiveTiers(t *testing.T) {
	cases := []struct {
		sev  findings.Severity
		want string
	}{
		{findings.SevCritical, "fsev-critical"},
		{findings.SevHigh, "fsev-high"},
		{findings.SevMedium, "fsev-medium"},
		{findings.SevLow, "fsev-low"},
		{findings.SevInfo, "fsev-info"},
		{findings.Severity("bogus"), "fsev-info"}, // default fallback
	}
	for _, c := range cases {
		if got := findingSevClass(c.sev); got != c.want {
			t.Errorf("findingSevClass(%q) = %q, want %q", c.sev, got, c.want)
		}
	}
}
