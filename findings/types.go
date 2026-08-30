// Package findings turns the raw signals a scan already collected
// (scanner.Report — TLS certs, HTTP headers, open ports, banners) into
// a security-assessment-shaped list of Finding values: named,
// evidenced, explained, and remediated observations, each with one of
// five severities.
//
// This is a deliberate second layer on top of scanner.Finding (see
// scanner/types.go), not a replacement for it. scanner.Finding is the
// low-level, port-scoped signal the scan engine itself raises inline
// while probing (info/warning/critical, three tiers, attached directly
// to a PortResult) — that system stays exactly as it was, still drives
// the original --format table/csv severity column and the original
// 0/1/2 warning/critical counts in scanner.Summary. This package reads
// a *finished* scanner.Report and re-derives a richer, five-tier
// (INFO/LOW/MEDIUM/HIGH/CRITICAL) Finding model from it — adding a
// stable ID, a human title, a "why it matters" description, and a
// remediation suggestion — which is what the risk engine, HTML report,
// and dashboard findings table in this round of work are built on.
//
// Everything here is deterministic and rule-based: no scoring model
// weights, no machine learning, no external lookups. A given
// scanner.Report always produces exactly the same []Finding.
package findings

// Severity is a five-tier security severity, deliberately NOT called
// or scored as CVSS — this project makes no CVSS claim anywhere,
// because it doesn't implement CVSS's actual vector/metric model. It's
// Bareport's own severity scale, documented as such.
type Severity string

const (
	SevInfo     Severity = "INFO"
	SevLow      Severity = "LOW"
	SevMedium   Severity = "MEDIUM"
	SevHigh     Severity = "HIGH"
	SevCritical Severity = "CRITICAL"
)

// Rank gives a total order over severities (higher = more severe), used
// for sorting findings worst-first and by the risk engine's point
// weighting (see risk/engine.go).
func (s Severity) Rank() int {
	switch s {
	case SevCritical:
		return 4
	case SevHigh:
		return 3
	case SevMedium:
		return 2
	case SevLow:
		return 1
	default:
		return 0
	}
}

// Finding is one named, evidenced security observation. Every field is
// populated directly from data the scan actually collected — nothing
// here is inferred beyond what's in the corresponding rule's doc
// comment (see tls.go, http.go, network.go).
type Finding struct {
	// ID is a short, stable, machine-readable identifier, e.g.
	// "TLS-EXPIRED-CERT" — stable across runs so a JSON consumer or the
	// baseline-diff logic can recognize "the same finding" appearing
	// twice without string-matching the human title.
	ID          string   `json:"id"`
	Severity    Severity `json:"severity"`
	Title       string   `json:"title"`
	Description string   `json:"description"` // what was detected, and why it matters
	Evidence    string   `json:"evidence"`    // the specific observed data backing this finding
	Target      string   `json:"target"`
	Port        int      `json:"port,omitempty"`
	Protocol    string   `json:"protocol,omitempty"`
	Remediation string   `json:"remediation"`
}
