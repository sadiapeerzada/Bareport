package findings

import (
	"sort"

	"bareport/scanner"
)

// Analyze walks a completed scanner.Report and returns every Finding
// the deterministic rules in this package produce. Called once, after
// a scan finishes — never during scanning — since every rule here reads
// already-collected data (TLSInfo, HTTPInfo, banners, port state) with
// no additional network activity of its own.
//
// Ordering is deterministic: findings are sorted by severity
// (worst first), then host, then port, so JSON/HTML/table output and
// the risk engine's tally are stable across runs of the same report —
// no dependency on map iteration order or goroutine completion order
// anywhere in this package.
func Analyze(r *scanner.Report) []Finding {
	var out []Finding

	for _, h := range r.Hosts {
		out = append(out, dnsFindings(h.Host, h.DNS)...)

		for i := range h.Ports {
			p := &h.Ports[i]

			out = append(out, networkFindings(h.Host, p)...)

			scheme := "http"
			if p.TLS != nil {
				scheme = "https"
				out = append(out, tlsFindings(h.Host, p.Port, p.TLS)...)
			}
			out = append(out, httpFindings(h.Host, p.Port, scheme, p.HTTP)...)
		}
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Severity.Rank() != out[j].Severity.Rank() {
			return out[i].Severity.Rank() > out[j].Severity.Rank()
		}
		if out[i].Target != out[j].Target {
			return out[i].Target < out[j].Target
		}
		return out[i].Port < out[j].Port
	})

	return out
}

// Counts tallies findings by severity — the shape both the risk engine
// and the terminal/HTML/dashboard summary displays need.
type Counts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// Total returns the sum across all severities.
func (c Counts) Total() int {
	return c.Critical + c.High + c.Medium + c.Low + c.Info
}

// CountBySeverity tallies a slice of Finding into Counts.
func CountBySeverity(fs []Finding) Counts {
	var c Counts
	for _, f := range fs {
		switch f.Severity {
		case SevCritical:
			c.Critical++
		case SevHigh:
			c.High++
		case SevMedium:
			c.Medium++
		case SevLow:
			c.Low++
		default:
			c.Info++
		}
	}
	return c
}
