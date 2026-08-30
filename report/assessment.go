package report

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"bareport/findings"
	"bareport/risk"
	"bareport/scanner"
)

// SecurityAssessment is the top-level shape written by --json (and
// --save) as of this round of work. It embeds scanner.Report by value,
// which Go's encoding/json flattens: every field scanner.Report already
// exposed (started_at, duration_ns, hosts, summary) is still present at
// the same top-level JSON keys it always was — so any existing
// consumer reading started_at/hosts/summary keeps working unchanged.
// New keys (target, scan, services, findings, risk) are additions, not
// replacements, per the backward-compatibility requirement.
type SecurityAssessment struct {
	scanner.Report

	Target   string             `json:"target"`
	Scan     ScanMeta           `json:"scan"`
	Services []ServiceSummary   `json:"services"`
	Findings []findings.Finding `json:"findings"`
	Risk     risk.Result        `json:"risk"`
}

// ScanMeta records the scan-level context that isn't tied to any one
// host: what was requested, when, and under which profile — useful for
// a report reader (human or machine) to know how the results were
// produced without re-deriving it from the CLI invocation.
type ScanMeta struct {
	Targets   []string  `json:"targets"`
	Profile   string    `json:"profile,omitempty"`
	StartedAt time.Time `json:"started_at"`
	Duration  string    `json:"duration"`
}

// ServiceSummary is one row of the flat "what's running where"
// inventory derived from a Report — the "services" section of the JSON
// schema, and the source data for the HTML report's "Detected
// Services" table and the dashboard's service count.
type ServiceSummary struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Service  string `json:"service"`
}

// BuildAssessment derives a SecurityAssessment from a finished
// scanner.Report: runs the findings engine, scores the result, and
// flattens the open-port list into a ServiceSummary inventory. This is
// the single place those three steps (Analyze -> Score -> summarize
// services) are wired together, so every output path (terminal
// summary, JSON, HTML, dashboard) that needs them calls this once
// rather than each re-deriving its own copy.
func BuildAssessment(r *scanner.Report, targets []string, profile string) *SecurityAssessment {
	fs := findings.Analyze(r)
	score := risk.Score(fs)

	var target string
	if len(targets) > 0 {
		target = targets[0]
		if len(targets) > 1 {
			target = fmt.Sprintf("%s (+%d more)", target, len(targets)-1)
		}
	}

	return &SecurityAssessment{
		Report:   *r,
		Target:   target,
		Services: serviceInventory(r),
		Findings: fs,
		Risk:     score,
		Scan: ScanMeta{
			Targets:   targets,
			Profile:   profile,
			StartedAt: r.StartedAt,
			Duration:  r.Duration.String(),
		},
	}
}

// serviceInventory flattens every open port across every host into a
// ServiceSummary row — the data backing the JSON schema's "services"
// array and the HTML/dashboard "Detected Services" tables.
func serviceInventory(r *scanner.Report) []ServiceSummary {
	var out []ServiceSummary
	for _, h := range r.Hosts {
		for _, p := range h.Ports {
			if p.State != scanner.StateOpen {
				continue
			}
			service := "unknown"
			if p.Banner != nil {
				service = p.Banner.Protocol
			}
			out = append(out, ServiceSummary{Host: h.Host, Port: p.Port, Protocol: p.Protocol, Service: service})
		}
	}
	return out
}

// WriteAssessmentJSON marshals a as indented JSON.
func WriteAssessmentJSON(w io.Writer, a *SecurityAssessment) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(a); err != nil {
		return fmt.Errorf("report: encoding assessment JSON: %w", err)
	}
	return nil
}

// LoadAssessment parses a previously-saved assessment JSON file (as
// written by WriteAssessmentJSON) — used by baseline/drift comparison
// (report/diff.go) to load both the "before" and "after" side.
//
// It also transparently accepts a plain scanner.Report-shaped JSON
// file (the older --json output shape, or anything written via the
// still-available WriteJSON) — encoding/json simply leaves Findings,
// Risk, Target, Scan, and Services at their zero values in that case,
// so an old saved report can still be loaded and diffed on its
// port-level data even without the newer fields.
func LoadAssessment(r io.Reader) (*SecurityAssessment, error) {
	var a SecurityAssessment
	dec := json.NewDecoder(r)
	if err := dec.Decode(&a); err != nil {
		return nil, fmt.Errorf("report: decoding assessment JSON: %w", err)
	}
	return &a, nil
}
