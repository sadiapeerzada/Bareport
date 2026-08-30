package report

// worstFinding, rank, colorizeState, colorizeSeverity, and aliveLabel
// are all unexported pure functions with no I/O dependency of their
// own — tests/report_test.go exercises WriteTable end-to-end (which
// touches all of these indirectly), but only along whatever specific
// finding/state shapes that one fixture happens to use. Testing them
// directly here, in-package, covers every branch exhaustively.

import (
	"testing"

	"bareport/scanner"
)

func TestWorstFinding_EmptySlice(t *testing.T) {
	sev, note := worstFinding(nil)
	if sev != "" {
		t.Errorf("expected empty severity for no findings, got %q", sev)
	}
	if note != "-" {
		t.Errorf("expected note '-' for no findings, got %q", note)
	}
}

func TestWorstFinding_SingleFinding_NoMoreSuffix(t *testing.T) {
	sev, note := worstFinding([]scanner.Finding{
		{Severity: scanner.SevWarning, Message: "missing header"},
	})
	if sev != scanner.SevWarning {
		t.Errorf("expected SevWarning, got %s", sev)
	}
	if note != "missing header" {
		t.Errorf("expected note without a '+N more' suffix for a single finding, got %q", note)
	}
}

func TestWorstFinding_PicksHighestSeverityAndCountsExtras(t *testing.T) {
	sev, note := worstFinding([]scanner.Finding{
		{Severity: scanner.SevInfo, Message: "self-signed"},
		{Severity: scanner.SevCritical, Message: "cert expired"},
		{Severity: scanner.SevWarning, Message: "missing header"},
	})
	if sev != scanner.SevCritical {
		t.Errorf("expected the critical finding to win regardless of order, got %s", sev)
	}
	want := "cert expired (+2 more)"
	if note != want {
		t.Errorf("expected note %q, got %q", want, note)
	}
}

func TestWorstFinding_FirstFindingWinsTiesOnEqualSeverity(t *testing.T) {
	sev, note := worstFinding([]scanner.Finding{
		{Severity: scanner.SevWarning, Message: "first warning"},
		{Severity: scanner.SevWarning, Message: "second warning"},
	})
	if sev != scanner.SevWarning {
		t.Errorf("expected SevWarning, got %s", sev)
	}
	if note != "first warning (+1 more)" {
		t.Errorf("expected the first equally-severe finding to be kept, got %q", note)
	}
}

func TestRank_AllSeveritiesAndUnknownDefault(t *testing.T) {
	cases := []struct {
		sev  scanner.Severity
		want int
	}{
		{scanner.SevCritical, 3},
		{scanner.SevWarning, 2},
		{scanner.SevInfo, 1},
		{scanner.Severity("bogus"), 0},
		{scanner.Severity(""), 0},
	}
	for _, c := range cases {
		if got := rank(c.sev); got != c.want {
			t.Errorf("rank(%q) = %d, want %d", c.sev, got, c.want)
		}
	}
}

func TestAliveLabel_BothBranches(t *testing.T) {
	if got := aliveLabel(true); got != "up (no open ports found)" {
		t.Errorf("aliveLabel(true) = %q", got)
	}
	if got := aliveLabel(false); got != "down/unreachable" {
		t.Errorf("aliveLabel(false) = %q", got)
	}
}

func TestColorizeSeverity_AllBranches(t *testing.T) {
	cases := []struct {
		sev  scanner.Severity
		want string
	}{
		{scanner.SevCritical, ansiRed + "critical" + ansiReset},
		{scanner.SevWarning, ansiYellow + "warning" + ansiReset},
		{scanner.SevInfo, ansiGreen + "info" + ansiReset},
		{scanner.Severity(""), "-"},
		{scanner.Severity("bogus"), "-"},
	}
	for _, c := range cases {
		if got := colorizeSeverity(c.sev); got != c.want {
			t.Errorf("colorizeSeverity(%q) = %q, want %q", c.sev, got, c.want)
		}
	}
}

func TestColorizeState_AllBranches(t *testing.T) {
	if got := colorizeState(scanner.StateOpen); got != ansiGreen+"open"+ansiReset {
		t.Errorf("colorizeState(open) = %q", got)
	}
	if got := colorizeState(scanner.StateClosed); got != "closed" {
		t.Errorf("colorizeState(closed) = %q, expected no color codes", got)
	}
	if got := colorizeState(scanner.StateFiltered); got != ansiYellow+"filtered"+ansiReset {
		t.Errorf("colorizeState(filtered) = %q", got)
	}
}

func TestSevClass_AllFourNamedTiersAndDefault(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"CRITICAL", "sev-critical"},
		{"HIGH", "sev-high"},
		{"MEDIUM", "sev-medium"},
		{"LOW", "sev-low"},
		{"INFO", "sev-info"},
		{"bogus", "sev-info"},
		{"", "sev-info"},
	}
	for _, c := range cases {
		if got := sevClass(c.in); got != c.want {
			t.Errorf("sevClass(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
