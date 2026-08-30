// Package config defines the scan configuration shape shared across the
// scanner, report, and web packages, and knows how to load/save it as a
// JSON "profile" so scans can be repeated without re-typing every flag.
//
// Why a separate package: main.go owns flag parsing (the CLI surface),
// but scanner/report/web all need the *resolved* settings without
// importing "flag" or knowing about the CLI at all. Centralizing the
// struct here avoids an import cycle (scanner would otherwise need to
// import main) and gives us one place to (de)serialize --config files.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Config holds every knob a scan run needs. It is deliberately a flat,
// JSON-serializable struct (no function fields, no channels) so it can
// round-trip through --config profile files unchanged.
type Config struct {
	// Targets: any mix of single hosts, CIDR ranges (e.g. "10.0.0.0/24"),
	// or "@path/to/file" to read newline-separated hosts from disk.
	Targets []string `json:"targets"`

	// Ports to scan. Empty means "use PortPreset" instead.
	Ports []int `json:"ports,omitempty"`
	// PortPreset is one of "top100", "top1000", or "" (use Ports as-is).
	PortPreset string `json:"port_preset,omitempty"`

	// UDPPorts, if non-empty, triggers a UDP probe pass on these ports
	// in addition to the TCP scan.
	UDPPorts []int `json:"udp_ports,omitempty"`

	Workers        int           `json:"workers"`
	ConnectTimeout time.Duration `json:"connect_timeout"`
	BannerTimeout  time.Duration `json:"banner_timeout"`
	// DNSTimeout bounds scanner.InspectDNS's entire set of lookups
	// (forward, MX, TXT, DMARC TXT, and reverse lookups). It's
	// separate from ConnectTimeout because DNS reconnaissance issues
	// several sequential resolver round-trips per host, not a single
	// connection attempt, and needs its own headroom accordingly.
	DNSTimeout time.Duration `json:"dns_timeout"`

	// SkipDiscovery disables the pre-scan "is this host up" liveness
	// check, forcing every port to be probed even on dead hosts.
	SkipDiscovery bool `json:"skip_discovery,omitempty"`

	// AdminPaths, if non-empty, opts into probing each listed path
	// (e.g. "admin", "manage") on every HTTP(S) target for an
	// unauthenticated response — see scanner/http.go's InspectHTTP doc
	// comment for why this is opt-in rather than always-on. Empty by
	// default: a normal scan never sends these extra requests.
	AdminPaths []string `json:"admin_paths,omitempty"`

	DoDNS     bool `json:"dns,omitempty"`
	DoTLS     bool `json:"tls,omitempty"`
	DoHTTP    bool `json:"http,omitempty"`
	DoBanners bool `json:"banners,omitempty"`
	DoFinger  bool `json:"fingerprint,omitempty"`
	DoMethods bool `json:"http_methods,omitempty"`

	OutputFormat string `json:"output_format,omitempty"` // "table" | "json" | "csv"
	NoColor      bool   `json:"no_color,omitempty"`
	NoLive       bool   `json:"no_live,omitempty"` // disable the live in-place terminal progress dashboard

	Serve     bool   `json:"serve,omitempty"`
	ServeAddr string `json:"serve_addr,omitempty"` // e.g. "127.0.0.1:0" for random port

	// Profile is one of "quick", "security", "full", or "" (no preset —
	// individual flags/defaults apply as-is). See main.go's applyProfile.
	Profile string `json:"profile,omitempty"`

	HTMLPath string `json:"html_path,omitempty"` // write a self-contained HTML security report here, if set
	SavePath string `json:"save_path,omitempty"` // write the assessment JSON here, if set (in addition to --format output)
	Minimal  bool   `json:"minimal,omitempty"`   // compact target/ports/risk-only terminal output
	Explain  bool   `json:"explain,omitempty"`   // print the long-form "What/Evidence/Recommendation" explanation for every finding
	Verbose  bool   `json:"verbose,omitempty"`   // emit structured (log/slog JSON) scan lifecycle logs to stderr, separate from the human-facing report on stdout

	// Watch, if set, turns a scan into continuous mode: re-scan every
	// WatchInterval, diffing each run against the previous one (via
	// report.CompareAssessments) and printing drift as it happens,
	// instead of requiring two manual --save runs and a separate
	// `bareport diff` invocation. Runs until canceled (Ctrl+C).
	Watch         bool          `json:"watch,omitempty"`
	WatchInterval time.Duration `json:"watch_interval,omitempty"`
}

// Default returns a Config with sane defaults, mirroring the flag
// defaults set in main.go. The scan behavior (ports, DNS/TLS/HTTP/
// fingerprint toggles) is derived from ApplyProfile("security") rather
// than duplicated here by hand, so a scan run with no --profile flag
// gets the same "security" posture the README documents as the
// standard assessment — the two can no longer drift apart the way they
// did before. Non-scan knobs (worker count, timeouts, output format)
// stay set directly here since profiles don't touch them.
func Default() Config {
	cfg := Config{
		Workers:        100,
		ConnectTimeout: 800 * time.Millisecond,
		BannerTimeout:  1500 * time.Millisecond,
		DNSTimeout:     3 * time.Second,
		OutputFormat:   "table",
		WatchInterval:  30 * time.Second,
	}
	cfg, err := ApplyProfile(cfg, "security")
	if err != nil {
		// Unreachable unless "security" itself is renamed/removed from
		// ApplyProfile without updating this call — fail loudly rather
		// than silently falling back to an unspecified config.
		panic("config: default profile failed to apply: " + err.Error())
	}
	return cfg
}

// Load reads a JSON config profile from disk and overlays it onto the
// given base config. Fields absent from the file (zero-valued) simply
// leave the base's value untouched EXCEPT slices/bools, which are
// replaced wholesale if present in the JSON — this mirrors how most
// JSON-config CLI tools behave and keeps the merge logic simple and
// predictable rather than doing deep field-by-field diffing.
func Load(path string, base Config) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return base, fmt.Errorf("config: opening %s: %w", path, err)
	}
	defer f.Close()

	cfg := base
	dec := json.NewDecoder(f)
	if err := dec.Decode(&cfg); err != nil {
		return base, fmt.Errorf("config: parsing %s: %w", path, err)
	}
	return cfg, nil
}

// Save writes cfg to path as indented JSON, so a working set of flags
// can be captured for reuse: `bareport ... --save-config prof.json`.
func Save(path string, cfg Config) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("config: creating %s: %w", path, err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(cfg); err != nil {
		return fmt.Errorf("config: writing %s: %w", path, err)
	}
	return nil
}

// ApplyProfile overlays one of the named scan profiles onto cfg,
// returning the modified copy. Profiles exist so `--profile security`
// is a memorable, documented shorthand for a specific combination of
// the individual flags below — they don't add any scanning logic of
// their own, just pick which of the scanner package's existing
// sub-scanners run and how thoroughly (port count, worker count).
//
//   - "quick":    fast triage. Top-100 ports, banners+TLS+HTTP on
//     (cheap, high signal), fingerprinting and DNS off (extra
//     round-trips that don't feed the findings engine), more workers
//     for speed.
//   - "security": the default posture for a security assessment.
//     Top-1000 ports, every inspector on (DNS/TLS/HTTP/banners) except
//     OS fingerprinting (a heuristic aside, not a security finding
//     input), moderate worker count.
//   - "full":     maximum coverage. Top-1000 ports, every inspector on
//     including fingerprinting, higher worker count to keep the wider
//     sweep from taking too long.
//
// An unrecognized profile name is left as an error for the caller to
// surface — ApplyProfile does not silently fall back to a default,
// since a typo'd profile name silently running the wrong scan would be
// a worse outcome than a clear error.
func ApplyProfile(cfg Config, profile string) (Config, error) {
	switch profile {
	case "":
		return cfg, nil
	case "quick":
		cfg.PortPreset = "top100"
		cfg.DoBanners = true
		cfg.DoTLS = true
		cfg.DoHTTP = true
		cfg.DoFinger = false
		cfg.DoDNS = false
		if cfg.Workers < 150 {
			cfg.Workers = 150
		}
	case "security":
		cfg.PortPreset = "top1000"
		cfg.DoBanners = true
		cfg.DoTLS = true
		cfg.DoHTTP = true
		cfg.DoDNS = true
		cfg.DoFinger = false
	case "full":
		cfg.PortPreset = "top1000"
		cfg.DoBanners = true
		cfg.DoTLS = true
		cfg.DoHTTP = true
		cfg.DoDNS = true
		cfg.DoFinger = true
		if cfg.Workers < 150 {
			cfg.Workers = 150
		}
	default:
		return cfg, fmt.Errorf("unknown profile %q (expected quick, security, or full)", profile)
	}
	cfg.Profile = profile
	return cfg, nil
}
