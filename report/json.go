package report

import (
	"encoding/json"
	"fmt"
	"io"

	"bareport/scanner"
)

// WriteJSON marshals r as indented JSON. Report and its nested types
// already carry `json:"..."` tags (see scanner/types.go), so this is a
// thin wrapper — the interesting design decision lives in the struct
// tags themselves, not here.
func WriteJSON(w io.Writer, r *scanner.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(r); err != nil {
		return fmt.Errorf("report: encoding JSON: %w", err)
	}
	return nil
}

// LoadJSON parses a previously-saved JSON report, used by diff mode
// (section 12) to load the "before" report for comparison.
func LoadJSON(r io.Reader) (*scanner.Report, error) {
	var report scanner.Report
	dec := json.NewDecoder(r)
	if err := dec.Decode(&report); err != nil {
		return nil, fmt.Errorf("report: decoding JSON: %w", err)
	}
	return &report, nil
}
