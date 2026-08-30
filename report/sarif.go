package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"bareport/findings"
)

// sarifSchemaURI and sarifVersion identify the exact SARIF version
// this writer targets. SARIF (Static Analysis Results Interchange
// Format) 2.1.0 is the OASIS-standardized JSON schema GitHub code
// scanning, Azure DevOps, and most CI security dashboards consume —
// emitting it is what lets `bareport --format sarif` results show up
// natively in a repo's "Security" tab rather than needing a bespoke
// parser on the consuming end.
const (
	sarifSchemaURI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
	sarifVersion   = "2.1.0"
)

// SARIF document structs. Only the subset of the full SARIF 2.1.0
// object model bareport actually populates is modeled here — SARIF's
// full schema is large (it covers things like code-flow graphs and
// fix suggestions this tool has no use for); encoding/json simply
// omits any field left as its zero value that has `omitempty`, so a
// minimal-but-valid document is the natural result of only defining
// the fields we fill in.
type sarifDocument struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri,omitempty"`
	Version        string      `json:"version,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string                 `json:"id"`
	ShortDescription sarifText              `json:"shortDescription"`
	FullDescription  sarifText              `json:"fullDescription"`
	Help             sarifText              `json:"help,omitempty"`
	Properties       map[string]interface{} `json:"properties,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"` // error | warning | note | none
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

// WriteSARIF renders a as a SARIF 2.1.0 document, built with stdlib
// encoding/json only — no SARIF SDK. See STDLIB.md for the explicit
// substitution rationale.
//
// Mapping notes (SARIF's object model is designed for static
// source-code analysis — file paths and line numbers — which doesn't
// map perfectly onto network findings, so a few pragmatic, documented
// choices were made rather than forcing a false fit):
//   - Each distinct Finding.ID becomes one SARIF "rule" (deduplicated),
//     with its Description/Remediation as the rule's descriptions —
//     this is what lets a code-scanning UI group multiple occurrences
//     of "TLS-EXPIRED-CERT" under one rule entry rather than listing
//     the rule metadata redundantly per occurrence.
//   - Each Finding becomes one SARIF "result" referencing its rule.
//   - There is no natural SARIF artifactLocation for a network
//     finding (no file path exists), so "host:port" (or bare host, if
//     no port applies — e.g. a DNS-level finding) is used as the URI
//     instead — a pragmatic stand-in that at least round-trips the
//     location information a human or tool would want, even though
//     it's not literally a file.
//   - Severity maps CRITICAL/HIGH -> "error", MEDIUM -> "warning",
//     LOW -> "note", INFO -> "none", following SARIF's own four-level
//     result severity enum as closely as bareport's five-tier model
//     allows (SARIF has no fifth level, so CRITICAL and HIGH both
//     collapse to "error" — the one lossy step in this mapping, noted
//     here rather than left implicit).
func WriteSARIF(w io.Writer, a *SecurityAssessment) error {
	doc := buildSARIF(a)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("report: encoding SARIF: %w", err)
	}
	return nil
}

func buildSARIF(a *SecurityAssessment) sarifDocument {
	rulesByID := map[string]sarifRule{}
	var results []sarifResult

	for _, f := range a.Findings {
		if _, exists := rulesByID[f.ID]; !exists {
			rulesByID[f.ID] = sarifRule{
				ID:               f.ID,
				ShortDescription: sarifText{Text: f.Title},
				FullDescription:  sarifText{Text: f.Description},
				Help:             sarifText{Text: f.Remediation},
				Properties: map[string]interface{}{
					"severity": string(f.Severity),
				},
			}
		}

		uri := f.Target
		if f.Port != 0 {
			uri = fmt.Sprintf("%s:%d", f.Target, f.Port)
		}

		results = append(results, sarifResult{
			RuleID:  f.ID,
			Level:   sarifLevel(f.Severity),
			Message: sarifText{Text: f.Description + " Evidence: " + f.Evidence},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: uri},
				},
			}},
		})
	}

	ids := make([]string, 0, len(rulesByID))
	for id := range rulesByID {
		ids = append(ids, id)
	}
	// Deterministic order — like every other output format in this
	// package, SARIF output for the same input should be reproducible
	// across runs, not dependent on Go's randomized map iteration.
	sort.Strings(ids)

	rules := make([]sarifRule, 0, len(ids))
	for _, id := range ids {
		rules = append(rules, rulesByID[id])
	}

	return sarifDocument{
		Schema:  sarifSchemaURI,
		Version: sarifVersion,
		Runs: []sarifRun{{
			Tool: sarifTool{
				Driver: sarifDriver{
					Name:           "bareport",
					InformationURI: "https://github.com/OWNER/REPO", // update once pushed
					Rules:          rules,
				},
			},
			Results: results,
		}},
	}
}

func sarifLevel(sev findings.Severity) string {
	switch sev {
	case findings.SevCritical, findings.SevHigh:
		return "error"
	case findings.SevMedium:
		return "warning"
	case findings.SevLow:
		return "note"
	default:
		return "none"
	}
}
