package risk

import (
	"sort"
	"strings"

	"bareport/findings"
)

// CategoryBreakdown is one category's contribution to the overall
// Bareport Risk Score — purely explanatory. It does not change what
// Score computes and is derived using the exact same severity weights
// Score itself uses (weightCritical..weightInfo, defined in
// engine.go); this file adds a second, additive view over that same
// arithmetic, not a second scoring model. Category assignment comes
// from the finding ID's own prefix (e.g. "TLS-EXPIRED-CERT" ->
// "TLS"), which findings/*.go already namespaces every rule under —
// see findings/network.go, findings/tls.go, findings/http.go,
// findings/dns.go — so this reads real structure already present in
// the finding list rather than introducing a new classification of
// its own.
type CategoryBreakdown struct {
	Category string          `json:"category"`
	Points   int             `json:"points"` // raw weighted points from this category's findings, uncapped by maxScore
	Counts   findings.Counts `json:"counts"`
}

// categoryPrefixes maps each finding-ID prefix findings/*.go actually
// uses to the human-readable category name shown in reports. Adding a
// findings package with a new prefix later just means adding one
// entry here — Breakdown itself needs no other change.
var categoryPrefixes = []struct {
	prefix   string
	category string
}{
	{"NET-", "Network"},
	{"TLS-", "TLS"},
	{"HTTP-", "HTTP"},
	{"DNS-", "DNS"},
}

// categoryOf returns the display category for a finding ID, or
// "Other" if it doesn't match any known prefix — so a future finding
// package that doesn't yet have a category entry above still shows up
// in the breakdown instead of silently vanishing from the total.
func categoryOf(id string) string {
	for _, c := range categoryPrefixes {
		if strings.HasPrefix(id, c.prefix) {
			return c.category
		}
	}
	return "Other"
}

// Breakdown groups fs by category and reports each category's raw
// point contribution and finding counts, sorted by points descending
// (the categories driving the score the most come first) with ties
// broken alphabetically for a stable, reproducible order.
//
// Points are the same per-severity weights Score() sums before
// capping at maxScore — so for a scan whose raw total is under 100,
// summing every CategoryBreakdown.Points here reproduces the overall
// Score exactly; for a scan whose raw total exceeds 100 (and is
// therefore capped), the categories still show their true relative
// contribution, which the cap intentionally discards from the
// headline number alone.
func Breakdown(fs []findings.Finding) []CategoryBreakdown {
	byCategory := map[string][]findings.Finding{}
	for _, f := range fs {
		cat := categoryOf(f.ID)
		byCategory[cat] = append(byCategory[cat], f)
	}

	out := make([]CategoryBreakdown, 0, len(byCategory))
	for cat, catFindings := range byCategory {
		counts := findings.CountBySeverity(catFindings)
		points := counts.Critical*weightCritical +
			counts.High*weightHigh +
			counts.Medium*weightMedium +
			counts.Low*weightLow +
			counts.Info*weightInfo
		out = append(out, CategoryBreakdown{Category: cat, Points: points, Counts: counts})
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Points != out[j].Points {
			return out[i].Points > out[j].Points
		}
		return out[i].Category < out[j].Category
	})
	return out
}
