package report

import (
	"fmt"
	"io"
	"sort"

	"bareport/findings"
	"bareport/risk"
)

// SecurityDrift extends the existing port-level Diff (see diff.go —
// unchanged, still available on its own via Compare/WriteDiff) into a
// full security-posture comparison between two SecurityAssessments:
// service changes, finding-level changes, TLS certificate changes, and
// the risk score delta. This is what `bareport diff baseline.json
// current.json` renders when both files carry the newer assessment
// shape (findings/risk/services) rather than just a bare port list.
type SecurityDrift struct {
	Ports *Diff `json:"ports"` // reuses the existing port-level Diff unchanged

	NewServices     []ServiceSummary `json:"new_services,omitempty"`
	RemovedServices []ServiceSummary `json:"removed_services,omitempty"`

	NewFindings      []findings.Finding `json:"new_findings,omitempty"`
	ResolvedFindings []findings.Finding `json:"resolved_findings,omitempty"`

	TLSCertChanges []TLSCertChange `json:"tls_certificate_changes,omitempty"`

	RiskBefore risk.Result `json:"risk_before"`
	RiskAfter  risk.Result `json:"risk_after"`
	RiskDelta  int         `json:"risk_delta"` // after.Score - before.Score; positive = worse
}

// TLSCertChange records a certificate that changed for a given
// host:port between the two scans — detected via Subject or NotAfter
// differing, which covers both a renewal (NotAfter moves forward) and
// a swap to a genuinely different certificate (Subject changes).
type TLSCertChange struct {
	PortRef
	BeforeSubject string `json:"before_subject"`
	AfterSubject  string `json:"after_subject"`
	BeforeExpiry  string `json:"before_expiry"`
	AfterExpiry   string `json:"after_expiry"`
}

// findingKey identifies "the same finding" across two scans: same rule
// ID at the same host:port. Two scans of a genuinely static target
// should produce identical keys for identical findings, which is what
// lets CompareAssessments tell "still present" apart from "new" or
// "resolved" rather than treating every finding as new every time.
type findingKey struct {
	id   string
	host string
	port int
}

func keyOf(f findings.Finding) findingKey {
	return findingKey{id: f.ID, host: f.Target, port: f.Port}
}

func serviceKey(s ServiceSummary) portKey {
	return portKey{host: s.Host, proto: s.Protocol, port: s.Port}
}

// CompareAssessments builds a SecurityDrift between two
// SecurityAssessments. Port-level comparison is delegated to the
// existing Compare (unchanged); everything else here is new.
func CompareAssessments(before, after *SecurityAssessment) *SecurityDrift {
	d := &SecurityDrift{
		Ports:      Compare(&before.Report, &after.Report),
		RiskBefore: before.Risk,
		RiskAfter:  after.Risk,
		RiskDelta:  after.Risk.Score - before.Risk.Score,
	}

	// Services: set difference by host:port:protocol key.
	beforeServices := make(map[portKey]ServiceSummary, len(before.Services))
	for _, s := range before.Services {
		beforeServices[serviceKey(s)] = s
	}
	afterServices := make(map[portKey]ServiceSummary, len(after.Services))
	for _, s := range after.Services {
		afterServices[serviceKey(s)] = s
	}
	for k, s := range afterServices {
		if _, existed := beforeServices[k]; !existed {
			d.NewServices = append(d.NewServices, s)
		}
	}
	for k, s := range beforeServices {
		if _, stillThere := afterServices[k]; !stillThere {
			d.RemovedServices = append(d.RemovedServices, s)
		}
	}
	sort.Slice(d.NewServices, func(i, j int) bool {
		return d.NewServices[i].Host+d.NewServices[i].Service < d.NewServices[j].Host+d.NewServices[j].Service
	})
	sort.Slice(d.RemovedServices, func(i, j int) bool {
		return d.RemovedServices[i].Host+d.RemovedServices[i].Service < d.RemovedServices[j].Host+d.RemovedServices[j].Service
	})

	// Findings: set difference by (rule ID, host, port).
	beforeFindings := make(map[findingKey]findings.Finding, len(before.Findings))
	for _, f := range before.Findings {
		beforeFindings[keyOf(f)] = f
	}
	afterFindings := make(map[findingKey]findings.Finding, len(after.Findings))
	for _, f := range after.Findings {
		afterFindings[keyOf(f)] = f
	}
	for k, f := range afterFindings {
		if _, existed := beforeFindings[k]; !existed {
			d.NewFindings = append(d.NewFindings, f)
		}
	}
	for k, f := range beforeFindings {
		if _, stillThere := afterFindings[k]; !stillThere {
			d.ResolvedFindings = append(d.ResolvedFindings, f)
		}
	}
	sort.SliceStable(d.NewFindings, func(i, j int) bool { return d.NewFindings[i].Severity.Rank() > d.NewFindings[j].Severity.Rank() })
	sort.SliceStable(d.ResolvedFindings, func(i, j int) bool {
		return d.ResolvedFindings[i].Severity.Rank() > d.ResolvedFindings[j].Severity.Rank()
	})

	// TLS certificate changes: for host:port pairs present with TLS
	// info on both sides, flag if the subject or expiry differs.
	beforePorts := indexPorts(&before.Report)
	afterPorts := indexPorts(&after.Report)
	for key, ap := range afterPorts {
		bp, existed := beforePorts[key]
		if !existed || ap.TLS == nil || bp.TLS == nil {
			continue
		}
		if ap.TLS.Subject != bp.TLS.Subject || !ap.TLS.NotAfter.Equal(bp.TLS.NotAfter) {
			d.TLSCertChanges = append(d.TLSCertChanges, TLSCertChange{
				PortRef:       PortRef{Host: ap.Host, Port: ap.Port},
				BeforeSubject: bp.TLS.Subject,
				AfterSubject:  ap.TLS.Subject,
				BeforeExpiry:  bp.TLS.NotAfter.Format("2006-01-02"),
				AfterExpiry:   ap.TLS.NotAfter.Format("2006-01-02"),
			})
		}
	}
	sort.Slice(d.TLSCertChanges, func(i, j int) bool { return d.TLSCertChanges[i].Host < d.TLSCertChanges[j].Host })

	return d
}

// HasChanges reports whether any drift was detected at all — used by
// WriteSecurityDrift to print a clean "no changes" message, and
// available to callers (e.g. a CI step) that only care about a
// yes/no answer.
func (d *SecurityDrift) HasChanges() bool {
	return len(d.Ports.NewOpenPorts) > 0 || len(d.Ports.ClosedPorts) > 0 ||
		len(d.Ports.NewlyExpiredCerts) > 0 || len(d.Ports.ChangedHeaders) > 0 ||
		len(d.NewServices) > 0 || len(d.RemovedServices) > 0 ||
		len(d.NewFindings) > 0 || len(d.ResolvedFindings) > 0 ||
		len(d.TLSCertChanges) > 0 || d.RiskDelta != 0
}

// WriteSecurityDrift renders a SecurityDrift as human-readable text in
// the "SECURITY DRIFT DETECTED" shape.
func WriteSecurityDrift(w io.Writer, d *SecurityDrift) error {
	if !d.HasChanges() {
		fmt.Fprintln(w, "No security drift detected — baseline and current scan match.")
		return nil
	}

	fmt.Fprintln(w, "SECURITY DRIFT DETECTED")
	fmt.Fprintln(w, "────────────────────────────────")
	fmt.Fprintln(w)

	for _, p := range d.Ports.NewOpenPorts {
		fmt.Fprintf(w, "+ PORT %d opened (%s)\n", p.Port, p.Host)
	}
	for _, s := range d.NewServices {
		fmt.Fprintf(w, "+ SERVICE %s detected on %s:%d\n", s.Service, s.Host, s.Port)
	}
	for _, c := range d.TLSCertChanges {
		fmt.Fprintf(w, "+ TLS certificate changed on %s:%d (%s -> %s)\n", c.Host, c.Port, c.BeforeExpiry, c.AfterExpiry)
	}
	for _, f := range d.NewFindings {
		fmt.Fprintf(w, "+ NEW %s finding: %s (%s:%d)\n", f.Severity, f.Title, f.Target, f.Port)
	}
	for _, c := range d.Ports.NewlyExpiredCerts {
		fmt.Fprintf(w, "+ TLS certificate newly expired on %s:%d\n", c.Host, c.Port)
	}

	fmt.Fprintln(w)
	for _, p := range d.Ports.ClosedPorts {
		fmt.Fprintf(w, "- PORT %d closed (%s)\n", p.Port, p.Host)
	}
	for _, s := range d.RemovedServices {
		fmt.Fprintf(w, "- SERVICE %s no longer detected on %s:%d\n", s.Service, s.Host, s.Port)
	}
	for _, f := range d.ResolvedFindings {
		fmt.Fprintf(w, "- RESOLVED %s finding: %s (%s:%d)\n", f.Severity, f.Title, f.Target, f.Port)
	}

	if len(d.Ports.ChangedHeaders) > 0 {
		fmt.Fprintln(w, "\nChanged security headers:")
		for _, c := range d.Ports.ChangedHeaders {
			fmt.Fprintf(w, "  ~ %s:%d %s: %q -> %q\n", c.Host, c.Port, c.Header, c.Before, c.After)
		}
	}

	fmt.Fprintln(w, "\nRisk:")
	fmt.Fprintf(w, "Baseline: %d (%s)\n", d.RiskBefore.Score, d.RiskBefore.Level)
	fmt.Fprintf(w, "Current:  %d (%s)\n", d.RiskAfter.Score, d.RiskAfter.Level)
	sign := "+"
	if d.RiskDelta < 0 {
		sign = ""
	}
	fmt.Fprintf(w, "\nChange: %s%d\n", sign, d.RiskDelta)

	return nil
}
