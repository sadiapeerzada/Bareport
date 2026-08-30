package report

import (
	"encoding/csv"
	"fmt"
	"io"
	"strconv"

	"bareport/scanner"
)

// csvHeader defines the flat column layout we export findings/ports
// into. CSV is inherently flat, so nested detail (banner hex-dumps,
// full SAN lists, every finding on a port) doesn't fit one row per
// port cleanly — we pick the single worst finding per row (same logic
// as the table view) and note when there were more, keeping CSV
// genuinely spreadsheet-friendly rather than JSON-crammed-into-cells.
var csvHeader = []string{
	"host", "port", "protocol", "state", "service", "tls_version",
	"cert_days_until_expiry", "http_status", "severity", "finding", "extra_findings",
}

// WriteCSV renders r using encoding/csv, which handles quoting/escaping
// of any commas or quotes inside messages automatically — the reason to
// use it instead of hand-joining strings with fmt.Sprintf.
func WriteCSV(w io.Writer, r *scanner.Report) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()

	if err := cw.Write(csvHeader); err != nil {
		return fmt.Errorf("report: writing CSV header: %w", err)
	}

	for _, h := range r.Hosts {
		for _, p := range h.Ports {
			service := ""
			if p.Banner != nil {
				service = p.Banner.Protocol
			}
			tlsVersion := ""
			certDays := ""
			if p.TLS != nil {
				tlsVersion = p.TLS.Version
				certDays = strconv.Itoa(p.TLS.DaysUntilExpiry)
			}
			httpStatus := ""
			if p.HTTP != nil {
				httpStatus = strconv.Itoa(p.HTTP.StatusCode)
			}
			sev, note := worstFinding(p.Findings)
			extra := ""
			if len(p.Findings) > 1 {
				extra = strconv.Itoa(len(p.Findings) - 1)
			}

			row := []string{
				p.Host, strconv.Itoa(p.Port), p.Protocol, string(p.State), service,
				tlsVersion, certDays, httpStatus, string(sev), note, extra,
			}
			if err := cw.Write(row); err != nil {
				return fmt.Errorf("report: writing CSV row for %s:%d: %w", p.Host, p.Port, err)
			}
		}
	}

	cw.Flush()
	if err := cw.Error(); err != nil {
		return fmt.Errorf("report: flushing CSV: %w", err)
	}
	return nil
}
