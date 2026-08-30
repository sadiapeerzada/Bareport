package report

import (
	"sort"

	"bareport/findings"
	"bareport/scanner"
)

// AttackSurfaceHost is one host's exposed surface — every open port,
// each annotated with the worst finding severity that applies to it —
// derived entirely from data a scan already collected (scanner.Report's
// host/port/protocol/banner and findings.Analyze's per-port findings).
// This is a view over existing report data, not a new scan step or a
// new finding source: nothing here changes what --json/--html/the
// existing Open Ports and Detected Services tables already show,
// which stay exactly as they are (see html_templates/report.html's
// existing sections 6 & 7 and web/templates/dashboard.html's existing
// port table) — this is an additional way of looking at the same
// data, not a replacement for either.
type AttackSurfaceHost struct {
	Host  string
	Alive bool
	Ports []AttackSurfacePort
}

// AttackSurfacePort is one open port on one host, as exposed attack
// surface: what it is (protocol + best-known service name) and how
// exposed it is (the worst-severity finding attached to that specific
// host:port, if any).
type AttackSurfacePort struct {
	Port         int
	Protocol     string
	Service      string
	Severity     string // "" if no findings at all for this host:port
	SevClass     string // sev-critical / sev-high / sev-medium / sev-low / sev-info / sev-none
	FindingCount int
}

// BuildAttackSurface derives the attack-surface view from a finished
// SecurityAssessment: for every alive host, every open port, with the
// worst severity among a.Findings scoped to that exact host:port
// (a.Findings is already the full, five-tier finding list findings.Analyze
// produced — the same source the risk score, the findings table, and
// risk.Breakdown's category view all read from, so this view is
// consistent with everything else derived from the same scan).
func BuildAttackSurface(a *SecurityAssessment) []AttackSurfaceHost {
	// index findings by host:port once, rather than re-scanning
	// a.Findings for every port — a scan with many open ports and many
	// findings would otherwise be O(hosts*ports*findings).
	type key struct {
		host string
		port int
	}
	byPort := map[key][]findings.Finding{}
	for _, f := range a.Findings {
		k := key{f.Target, f.Port}
		byPort[k] = append(byPort[k], f)
	}

	var out []AttackSurfaceHost
	for _, h := range a.Hosts {
		ah := AttackSurfaceHost{Host: h.Host, Alive: h.Alive}
		for _, p := range h.Ports {
			if p.State != scanner.StateOpen {
				continue
			}
			fs := byPort[key{h.Host, p.Port}]
			sev, sevClass := worstFindingSeverity(fs)
			ah.Ports = append(ah.Ports, AttackSurfacePort{
				Port: p.Port, Protocol: p.Protocol, Service: attackSurfaceService(p.Banner),
				Severity: sev, SevClass: sevClass, FindingCount: len(fs),
			})
		}
		if len(ah.Ports) > 0 {
			sort.Slice(ah.Ports, func(i, j int) bool { return ah.Ports[i].Port < ah.Ports[j].Port })
			out = append(out, ah)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	return out
}

func attackSurfaceService(b *scanner.Banner) string {
	if b == nil {
		return "unknown"
	}
	return b.Protocol
}

// worstFindingSeverity mirrors web/server.go's worstSeverity in
// spirit (worst-first over a finding list) but operates on the
// top-level, five-tier findings.Finding rather than scanner's
// three-tier embedded scanner.Finding, since AttackSurfacePort scopes
// findings by exact host:port from a.Findings — the richer, primary
// finding list every other view (risk score, risk.Breakdown, the
// findings table) already reads from.
func worstFindingSeverity(fs []findings.Finding) (string, string) {
	if len(fs) == 0 {
		return "", "sev-none"
	}
	worst := findings.SevInfo
	for _, f := range fs {
		if f.Severity.Rank() > worst.Rank() {
			worst = f.Severity
		}
	}
	return string(worst), sevClass(string(worst))
}
