package report

import (
	"fmt"
	"io"

	"bareport/scanner"
)

// Diff summarizes what changed between two scans of (presumably) the
// same targets over time: newly opened/closed ports, certs that
// expired since the last run, and header changes. This is what makes
// "rescan this host periodically" demo well (section 12).
type Diff struct {
	NewOpenPorts      []PortRef      `json:"new_open_ports,omitempty"`
	ClosedPorts       []PortRef      `json:"closed_ports,omitempty"` // was open before, isn't now
	NewlyExpiredCerts []PortRef      `json:"newly_expired_certs,omitempty"`
	ChangedHeaders    []HeaderChange `json:"changed_headers,omitempty"`
}

// PortRef identifies a single host:port for diff output.
type PortRef struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

// HeaderChange records a security header whose value differs between
// the two scans for a given host:port.
type HeaderChange struct {
	PortRef
	Header string `json:"header"`
	Before string `json:"before"`
	After  string `json:"after"`
}

// Compare builds a Diff between an earlier report `before` and a later
// report `after`. Matching is done purely by host:port key — reports
// from different target sets will simply show everything in `after`
// not present in `before` as "new".
func Compare(before, after *scanner.Report) *Diff {
	beforePorts := indexPorts(before)
	afterPorts := indexPorts(after)

	d := &Diff{}

	for key, ap := range afterPorts {
		bp, existed := beforePorts[key]

		if ap.State == scanner.StateOpen && (!existed || bp.State != scanner.StateOpen) {
			d.NewOpenPorts = append(d.NewOpenPorts, PortRef{Host: ap.Host, Port: ap.Port})
		}

		if existed && ap.TLS != nil && bp.TLS != nil {
			wasValid := bp.TLS.DaysUntilExpiry >= 0
			nowExpired := ap.TLS.DaysUntilExpiry < 0
			if wasValid && nowExpired {
				d.NewlyExpiredCerts = append(d.NewlyExpiredCerts, PortRef{Host: ap.Host, Port: ap.Port})
			}
		}

		if existed && ap.HTTP != nil && bp.HTTP != nil {
			for header, afterVal := range ap.HTTP.SecurityHeaders {
				beforeVal := bp.HTTP.SecurityHeaders[header]
				if beforeVal != afterVal {
					d.ChangedHeaders = append(d.ChangedHeaders, HeaderChange{
						PortRef: PortRef{Host: ap.Host, Port: ap.Port},
						Header:  header,
						Before:  beforeVal,
						After:   afterVal,
					})
				}
			}
		}
	}

	for key, bp := range beforePorts {
		if bp.State != scanner.StateOpen {
			continue
		}
		ap, existsNow := afterPorts[key]
		if !existsNow || ap.State != scanner.StateOpen {
			d.ClosedPorts = append(d.ClosedPorts, PortRef{Host: bp.Host, Port: bp.Port})
		}
	}

	return d
}

// portKey identifies a host:port:protocol triple for matching between
// two reports.
type portKey struct {
	host, proto string
	port        int
}

func indexPorts(r *scanner.Report) map[portKey]scanner.PortResult {
	idx := make(map[portKey]scanner.PortResult)
	for _, h := range r.Hosts {
		for _, p := range h.Ports {
			idx[portKey{host: p.Host, proto: p.Protocol, port: p.Port}] = p
		}
	}
	return idx
}

// WriteDiff renders a Diff as human-readable text.
func WriteDiff(w io.Writer, d *Diff) error {
	fmt.Fprintln(w, "=== Scan Diff ===")

	if len(d.NewOpenPorts) == 0 && len(d.ClosedPorts) == 0 && len(d.NewlyExpiredCerts) == 0 && len(d.ChangedHeaders) == 0 {
		fmt.Fprintln(w, "No changes detected.")
		return nil
	}

	if len(d.NewOpenPorts) > 0 {
		fmt.Fprintln(w, "\nNewly open ports:")
		for _, p := range d.NewOpenPorts {
			fmt.Fprintf(w, "  + %s:%d\n", p.Host, p.Port)
		}
	}
	if len(d.ClosedPorts) > 0 {
		fmt.Fprintln(w, "\nNewly closed ports:")
		for _, p := range d.ClosedPorts {
			fmt.Fprintf(w, "  - %s:%d\n", p.Host, p.Port)
		}
	}
	if len(d.NewlyExpiredCerts) > 0 {
		fmt.Fprintln(w, "\nCertificates newly expired:")
		for _, p := range d.NewlyExpiredCerts {
			fmt.Fprintf(w, "  ! %s:%d\n", p.Host, p.Port)
		}
	}
	if len(d.ChangedHeaders) > 0 {
		fmt.Fprintln(w, "\nChanged security headers:")
		for _, c := range d.ChangedHeaders {
			fmt.Fprintf(w, "  ~ %s:%d %s: %q -> %q\n", c.Host, c.Port, c.Header, c.Before, c.After)
		}
	}
	return nil
}
