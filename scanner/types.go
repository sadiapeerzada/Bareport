// Package scanner implements the concurrent network reconnaissance
// engine: TCP/UDP port scanning, host discovery, banner grabbing,
// OS fingerprinting, TLS inspection, HTTP auditing, and DNS lookups.
//
// Design note: every sub-scanner (tcp.go, tls.go, http.go, ...) is a
// small, independently testable unit that takes a context.Context and
// returns a typed result plus an error. main.go / a future Orchestrator
// wires them together. This keeps each file honest about exactly one
// stdlib-driven concern, which matters a lot when re-explaining "why is
// this package used here" from memory later.
package scanner

import "time"

// PortState is the tri-state result of probing a single port. UDP scans
// can only ever produce Open or OpenFiltered (see udp.go for why),
// while TCP scans can confidently report all three.
type PortState string

const (
	StateOpen         PortState = "open"
	StateClosed       PortState = "closed"
	StateFiltered     PortState = "filtered"      // no response at all (firewall likely)
	StateOpenFiltered PortState = "open|filtered" // UDP: can't tell open from filtered
)

// Severity classifies a Finding for the warning system (section 10).
type Severity string

const (
	SevInfo     Severity = "info"
	SevWarning  Severity = "warning"
	SevCritical Severity = "critical"
)

// Finding is one rule-triggered observation attached to a PortResult,
// e.g. "certificate expires in 12 days" or "X-Frame-Options missing".
// Findings are what the severity/exit-code system (section 10, 13) and
// the web dashboard's findings table both consume.
type Finding struct {
	Severity Severity `json:"severity"`
	Rule     string   `json:"rule"`    // short machine-stable id, e.g. "cert-expiring"
	Message  string   `json:"message"` // human-readable detail
}

// Banner holds whatever banner.go managed to grab and parse from a
// freshly opened connection.
type Banner struct {
	Protocol string `json:"protocol"`           // "ssh", "http", "ftp", "smtp", "raw"
	Raw      string `json:"raw,omitempty"`      // text banner if printable
	HexDump  string `json:"hex_dump,omitempty"` // fallback for unrecognized binary protocols
}

// Fingerprint holds OS/service heuristics derived from a live connection.
// Everything here is explicitly a guess — see fingerprint.go — and the
// struct's doc comments/JSON tags say so to avoid the report implying
// certainty it doesn't have.
type Fingerprint struct {
	TTL       int    `json:"ttl"`
	OSGuess   string `json:"os_guess"`  // e.g. "Linux/BSD (heuristic)"
	Heuristic string `json:"heuristic"` // explanation shown in reports/UI
}

// TLSInfo is the result of a TLS handshake + certificate inspection.
type TLSInfo struct {
	Version         string    `json:"version"`
	CipherSuite     string    `json:"cipher_suite"`
	Subject         string    `json:"subject"`
	Issuer          string    `json:"issuer"`
	NotAfter        time.Time `json:"not_after"`
	DaysUntilExpiry int       `json:"days_until_expiry"`
	SelfSigned      bool      `json:"self_signed"`
	SANs            []string  `json:"sans,omitempty"`
}

// HTTPInfo is the result of an HTTP fetch + security header audit.
type HTTPInfo struct {
	StatusCode      int               `json:"status_code"`
	Server          string            `json:"server,omitempty"`
	FinalURL        string            `json:"final_url"`
	RedirectChain   []string          `json:"redirect_chain,omitempty"`
	HTTPSUpgrade    bool              `json:"https_upgrade"`    // did http:// redirect to https://?
	SecurityHeaders map[string]string `json:"security_headers"` // header name -> value, "" if missing
	AllowedMethods  []string          `json:"allowed_methods,omitempty"`
	DangerousOpen   []string          `json:"dangerous_methods_open,omitempty"`

	// Cookies is every cookie the response set, as parsed by net/http's
	// own Set-Cookie parsing (http.Response.Cookies()) — no hand-rolled
	// parsing here. Populated whenever the response sets at least one
	// cookie; nil otherwise.
	Cookies []CookieInfo `json:"cookies,omitempty"`

	// ExposedAdminPaths lists any path from --admin-paths (opt-in,
	// empty by default — see config.Config.AdminPaths) that responded
	// with content and no authentication challenge. Empty unless
	// --admin-paths was explicitly set for this scan.
	ExposedAdminPaths []string `json:"exposed_admin_paths,omitempty"`
}

// CookieInfo is the security-relevant subset of a parsed Set-Cookie
// header: enough for findings/http.go's insecure-cookie rule to judge
// without needing the full net/http.Cookie type (which also carries
// fields like Expires/MaxAge that aren't security-relevant here).
type CookieInfo struct {
	Name     string `json:"name"`
	Secure   bool   `json:"secure"`
	HttpOnly bool   `json:"http_only"`
	SameSite string `json:"same_site,omitempty"` // "Strict" | "Lax" | "None" | "" (unset)
}

// DNSInfo is the result of section 8's stdlib-only DNS reconnaissance.
type DNSInfo struct {
	Addresses  []string `json:"addresses,omitempty"`
	MXRecords  []string `json:"mx_records,omitempty"`
	TXTRecords []string `json:"txt_records,omitempty"`
	PTR        []string `json:"ptr,omitempty"`
	HasSPF     bool     `json:"has_spf"`
	HasDMARC   bool     `json:"has_dmarc"`
}

// PortResult aggregates everything learned about a single host:port pair.
type PortResult struct {
	Host        string        `json:"host"`
	Port        int           `json:"port"`
	Protocol    string        `json:"protocol"` // "tcp" or "udp"
	State       PortState     `json:"state"`
	Latency     time.Duration `json:"latency_ns"`
	Banner      *Banner       `json:"banner,omitempty"`
	Fingerprint *Fingerprint  `json:"fingerprint,omitempty"`
	TLS         *TLSInfo      `json:"tls,omitempty"`
	HTTP        *HTTPInfo     `json:"http,omitempty"`
	Findings    []Finding     `json:"findings,omitempty"`
}

// HostResult aggregates all port results and DNS info for one host.
type HostResult struct {
	Host  string       `json:"host"`
	Alive bool         `json:"alive"`
	DNS   *DNSInfo     `json:"dns,omitempty"`
	Ports []PortResult `json:"ports"`
}

// Report is the top-level output of a full scan run: what report/json.go,
// report/csv.go, report/table.go, and web/server.go all render.
type Report struct {
	StartedAt time.Time     `json:"started_at"`
	Duration  time.Duration `json:"duration_ns"`
	Hosts     []HostResult  `json:"hosts"`

	// Summary is computed once at the end (see Summarize) so every
	// output format can just read it instead of re-walking Hosts.
	Summary Summary `json:"summary"`
}

// Summary holds the aggregate stats shown in section 9's summary line
// and the web dashboard's stat-card row (section 14).
type Summary struct {
	HostsScanned int `json:"hosts_scanned"`
	HostsAlive   int `json:"hosts_alive"`
	PortsOpen    int `json:"ports_open"`
	Warnings     int `json:"warnings"`
	Criticals    int `json:"criticals"`
}

// Summarize walks r.Hosts and (re)computes r.Summary in place. Called
// once after a scan completes; report/diff.go also calls it after
// filtering hosts for a diff view.
func (r *Report) Summarize() {
	s := Summary{}
	for _, h := range r.Hosts {
		s.HostsScanned++
		if h.Alive {
			s.HostsAlive++
		}
		for _, p := range h.Ports {
			if p.State == StateOpen {
				s.PortsOpen++
			}
			for _, f := range p.Findings {
				switch f.Severity {
				case SevWarning:
					s.Warnings++
				case SevCritical:
					s.Criticals++
				}
			}
		}
	}
	r.Summary = s
}

// ExitCode implements the ORIGINAL three-tier exit scheme (0 = clean,
// 1 = warnings present, 2 = criticals present) from before the
// findings/risk engine existed.
//
// Deprecated: this method is no longer what the CLI actually uses for
// its process exit code — main.go now calls risk.Result.ExitCode()
// instead, which implements the newer, documented 0/1/2/3 scheme (see
// README.md's "Exit codes" section). This method is kept, exported,
// and still correct on its own terms (it still reports accurately
// against scanner.Summary's warning/critical counts) for any existing
// caller relying on the original three-tier behavior directly against
// a bare scanner.Report — but new code should use
// risk.Result.ExitCode() via report.BuildAssessment, not this.
func (r *Report) ExitCode() int {
	switch {
	case r.Summary.Criticals > 0:
		return 2
	case r.Summary.Warnings > 0:
		return 1
	default:
		return 0
	}
}
