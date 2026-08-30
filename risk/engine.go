// Package risk implements the Bareport Risk Score: a deterministic,
// documented, non-CVSS scoring model that turns a []findings.Finding
// into a single 0-100 number plus a four-tier level.
//
// This is explicitly NOT a CVSS score, is never labeled as one, and
// makes no claim to be — CVSS is a specific, standardized vector/metric
// model (attack vector, complexity, privileges required, scope,
// confidentiality/integrity/availability impact) that this package
// does not implement. "Bareport Risk Score" is its own named thing:
// simple, transparent, and reproducible from the finding list alone.
package risk

import "bareport/findings"

// Point weights per severity. Deliberately simple integer weights
// rather than a more elaborate formula (e.g. no diminishing returns,
// no interaction terms between findings) — the goal is a score anyone
// can recompute by hand from the finding counts, not a black box.
const (
	weightCritical = 40
	weightHigh     = 20
	weightMedium   = 10
	weightLow      = 5
	weightInfo     = 0
)

// maxScore caps the score at 100 rather than growing unbounded with
// finding count, so a target with many overlapping medium findings
// doesn't produce a number that reads as "worse than critically
// compromised" — 100 means "as bad as this scale goes," not "sum of
// every point ever earned."
const maxScore = 100

// Level thresholds. Chosen so a single critical finding (40 points)
// alone lands solidly in HIGH, and it takes either one critical plus
// something else, or a cluster of high-severity findings, to reach
// CRITICAL — reflecting that one bad finding is serious but a scan
// riddled with independently-serious findings is worse than the sum of
// any one of them in isolation.
const (
	levelLowMax      = 19
	levelModerateMax = 39
	levelHighMax     = 69
	// 70-100 is CRITICAL.
)

// Result is the output of Score: the numeric score, its named level,
// and the finding counts the score was computed from (so a consumer
// never has to recompute Counts separately to explain the number).
type Result struct {
	Score  int             `json:"score"`
	Level  string          `json:"level"`
	Counts findings.Counts `json:"counts"`
}

// Score computes the Bareport Risk Score from a finding list. Pure
// function of its input: the same []findings.Finding always produces
// the same Result, with no hidden state or randomness — a requirement
// for the baseline-diff feature (report/diff.go) to meaningfully report
// "risk score changed from X to Y" across two separate scans.
func Score(fs []findings.Finding) Result {
	counts := findings.CountBySeverity(fs)

	raw := counts.Critical*weightCritical +
		counts.High*weightHigh +
		counts.Medium*weightMedium +
		counts.Low*weightLow +
		counts.Info*weightInfo

	score := raw
	if score > maxScore {
		score = maxScore
	}
	if score < 0 {
		score = 0
	}

	return Result{
		Score:  score,
		Level:  levelFor(score),
		Counts: counts,
	}
}

func levelFor(score int) string {
	switch {
	case score <= levelLowMax:
		return "LOW"
	case score <= levelModerateMax:
		return "MODERATE"
	case score <= levelHighMax:
		return "HIGH"
	default:
		return "CRITICAL"
	}
}

// ExitCode implements the CI-friendly exit code scheme documented in
// README.md:
//
//	0 = scan completed, no findings at all
//	2 = security findings detected (any severity, no critical)
//	3 = critical security findings detected
//
// (Exit code 1 — tool/scan error — is not produced here; that's a
// process-level outcome decided in main.go before a Result even
// exists, e.g. a bad flag or a scan that couldn't run at all.)
func (r Result) ExitCode() int {
	if r.Counts.Critical > 0 {
		return 3
	}
	if r.Counts.Total() > 0 {
		return 2
	}
	return 0
}
