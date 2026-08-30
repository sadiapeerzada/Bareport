package tests

import (
	"testing"

	"bareport/findings"
	"bareport/risk"
)

func mkFinding(sev findings.Severity) findings.Finding {
	return findings.Finding{ID: "TEST", Severity: sev, Title: "test finding"}
}

func TestRiskScore_NoFindings(t *testing.T) {
	r := risk.Score(nil)
	if r.Score != 0 {
		t.Errorf("expected score 0 for no findings, got %d", r.Score)
	}
	if r.Level != "LOW" {
		t.Errorf("expected level LOW for score 0, got %s", r.Level)
	}
}

func TestRiskScore_SingleCritical(t *testing.T) {
	r := risk.Score([]findings.Finding{mkFinding(findings.SevCritical)})
	if r.Score != 40 {
		t.Errorf("expected score 40 for one critical, got %d", r.Score)
	}
	if r.Level != "HIGH" {
		t.Errorf("expected level HIGH for score 40, got %s", r.Level)
	}
	if r.Counts.Critical != 1 {
		t.Errorf("expected Counts.Critical=1, got %d", r.Counts.Critical)
	}
}

func TestRiskScore_CapsAt100(t *testing.T) {
	fs := []findings.Finding{
		mkFinding(findings.SevCritical),
		mkFinding(findings.SevCritical),
		mkFinding(findings.SevCritical),
		mkFinding(findings.SevCritical), // 4 * 40 = 160, should cap at 100
	}
	r := risk.Score(fs)
	if r.Score != 100 {
		t.Errorf("expected score capped at 100, got %d", r.Score)
	}
	if r.Level != "CRITICAL" {
		t.Errorf("expected level CRITICAL for score 100, got %s", r.Level)
	}
}

func TestRiskScore_LevelBoundaries(t *testing.T) {
	cases := []struct {
		fs    []findings.Finding
		want  string
		score int
	}{
		{nil, "LOW", 0},
		{[]findings.Finding{mkFinding(findings.SevLow), mkFinding(findings.SevLow), mkFinding(findings.SevLow)}, "LOW", 15}, // 3*5=15
		{[]findings.Finding{mkFinding(findings.SevMedium), mkFinding(findings.SevMedium)}, "MODERATE", 20},                  // 2*10=20
		{[]findings.Finding{mkFinding(findings.SevHigh), mkFinding(findings.SevMedium)}, "MODERATE", 30},                    // 20+10=30, still <=39
		{[]findings.Finding{mkFinding(findings.SevCritical)}, "HIGH", 40},                                                   // 40, >39 and <=69
		{[]findings.Finding{mkFinding(findings.SevCritical), mkFinding(findings.SevCritical)}, "CRITICAL", 80},              // 80, >69
	}
	for i, c := range cases {
		r := risk.Score(c.fs)
		if r.Score != c.score {
			t.Errorf("case %d: expected score %d, got %d", i, c.score, r.Score)
		}
		if r.Level != c.want {
			t.Errorf("case %d: expected level %s, got %s (score %d)", i, c.want, r.Level, r.Score)
		}
	}
}

func TestRiskScore_Deterministic(t *testing.T) {
	fs := []findings.Finding{
		mkFinding(findings.SevCritical),
		mkFinding(findings.SevHigh),
		mkFinding(findings.SevMedium),
		mkFinding(findings.SevLow),
		mkFinding(findings.SevInfo),
	}
	r1 := risk.Score(fs)
	r2 := risk.Score(fs)
	if r1 != r2 {
		t.Errorf("Score is not deterministic: %+v != %+v", r1, r2)
	}
	wantScore := 40 + 20 + 10 + 5 + 0
	if r1.Score != wantScore {
		t.Errorf("expected score %d, got %d", wantScore, r1.Score)
	}
}

func TestSeverityRank_Ordering(t *testing.T) {
	if findings.SevCritical.Rank() <= findings.SevHigh.Rank() {
		t.Error("CRITICAL should rank above HIGH")
	}
	if findings.SevHigh.Rank() <= findings.SevMedium.Rank() {
		t.Error("HIGH should rank above MEDIUM")
	}
	if findings.SevMedium.Rank() <= findings.SevLow.Rank() {
		t.Error("MEDIUM should rank above LOW")
	}
	if findings.SevLow.Rank() <= findings.SevInfo.Rank() {
		t.Error("LOW should rank above INFO")
	}
}

func mkFindingID(id string, sev findings.Severity) findings.Finding {
	return findings.Finding{ID: id, Severity: sev, Title: "test finding"}
}

func TestRiskBreakdown_GroupsByIDPrefix(t *testing.T) {
	fs := []findings.Finding{
		mkFindingID("TLS-EXPIRED-CERT", findings.SevCritical),
		mkFindingID("TLS-SELF-SIGNED-CERT", findings.SevMedium),
		mkFindingID("HTTP-MISSING-HSTS", findings.SevMedium),
		mkFindingID("NET-OPEN-PORT", findings.SevInfo),
		mkFindingID("DNS-MISSING-SPF", findings.SevLow),
	}
	bd := risk.Breakdown(fs)

	byCat := map[string]risk.CategoryBreakdown{}
	for _, c := range bd {
		byCat[c.Category] = c
	}

	if got := byCat["TLS"].Points; got != 40+10 {
		t.Errorf("expected TLS points 50 (1 critical + 1 medium), got %d", got)
	}
	if got := byCat["TLS"].Counts.Critical; got != 1 {
		t.Errorf("expected TLS critical count 1, got %d", got)
	}
	if got := byCat["HTTP"].Points; got != 10 {
		t.Errorf("expected HTTP points 10, got %d", got)
	}
	if got := byCat["NET"]; got.Category != "" {
		t.Errorf("did not expect a bare 'NET' category (should be 'Network'), got %+v", got)
	}
	if got := byCat["Network"].Points; got != 0 {
		t.Errorf("expected Network points 0 (info-only), got %d", got)
	}
	if got := byCat["DNS"].Points; got != 5 {
		t.Errorf("expected DNS points 5, got %d", got)
	}
}

func TestRiskBreakdown_SortedByPointsDescending(t *testing.T) {
	fs := []findings.Finding{
		mkFindingID("DNS-MISSING-SPF", findings.SevLow),       // 5
		mkFindingID("TLS-EXPIRED-CERT", findings.SevCritical), // 40
		mkFindingID("HTTP-MISSING-HSTS", findings.SevMedium),  // 10
	}
	bd := risk.Breakdown(fs)
	if len(bd) != 3 {
		t.Fatalf("expected 3 categories, got %d", len(bd))
	}
	if bd[0].Category != "TLS" || bd[0].Points != 40 {
		t.Errorf("expected TLS (40 points) first, got %+v", bd[0])
	}
	if bd[1].Category != "HTTP" || bd[1].Points != 10 {
		t.Errorf("expected HTTP (10 points) second, got %+v", bd[1])
	}
	if bd[2].Category != "DNS" || bd[2].Points != 5 {
		t.Errorf("expected DNS (5 points) third, got %+v", bd[2])
	}
}

func TestRiskBreakdown_SumsMatchOverallScore_WhenUncapped(t *testing.T) {
	fs := []findings.Finding{
		mkFindingID("TLS-EXPIRED-CERT", findings.SevHigh),    // 20
		mkFindingID("HTTP-MISSING-HSTS", findings.SevMedium), // 10
		mkFindingID("NET-OPEN-PORT", findings.SevLow),        // 5
	}
	overall := risk.Score(fs)
	bd := risk.Breakdown(fs)

	sum := 0
	for _, c := range bd {
		sum += c.Points
	}
	if sum != overall.Score {
		t.Errorf("expected category points to sum to the (uncapped) overall score %d, got %d", overall.Score, sum)
	}
}

func TestRiskBreakdown_EmptyForNoFindings(t *testing.T) {
	bd := risk.Breakdown(nil)
	if len(bd) != 0 {
		t.Errorf("expected no categories for no findings, got %+v", bd)
	}
}
