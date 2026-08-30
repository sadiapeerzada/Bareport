package scanner

import (
	"context"
	"log"
	"sync/atomic"
	"time"

	"bareport/config"
)

// ProgressSnapshot is a point-in-time summary of an in-progress scan,
// emitted via an optional ProgressFunc passed to Run. It exists so the
// live terminal dashboard (report.LiveDashboard) — or any other
// consumer, like a future JSON progress stream — can render "how far
// along is this scan" without reaching into Report internals or
// re-walking HostResult slices on every tick.
type ProgressSnapshot struct {
	HostsDone, HostsTotal int
	PortsDone, PortsTotal int
	Warnings, Criticals   int
	Elapsed               time.Duration
}

// ProgressFunc receives a ProgressSnapshot each time Run has new
// information to report. It may be called frequently (once per
// completed port probe) and from a single goroutine only — Run never
// calls it concurrently — so implementations don't need their own
// locking around the snapshot itself, though they DO need locking if
// they hand the snapshot off to another goroutine (see
// report.LiveDashboard.Update for exactly that pattern).
type ProgressFunc func(ProgressSnapshot)

// Run executes a full scan according to cfg and returns the assembled
// Report. This is the single entry point main.go calls — it owns the
// pipeline order: discovery -> TCP scan -> UDP scan -> per-open-port
// enrichment (banners/fingerprint/TLS/HTTP) -> DNS -> findings ->
// summary.
//
// Every stage checks ctx.Done() so Ctrl+C (wired to cancel ctx in
// main.go) stops the pipeline promptly instead of running every
// remaining stage to completion.
//
// onProgress is optional (variadic, so the pre-existing two-argument
// call shape keeps compiling); if given, Run reports a ProgressSnapshot
// after every completed port probe and after every enriched port,
// using atomic counters (sync/atomic) rather than a mutex since these
// are simple independent counters, not a compound value needing
// atomicity across fields — only the final read into a ProgressSnapshot
// struct needs to happen after the increments it reports on.
func Run(ctx context.Context, cfg config.Config, onProgress ...ProgressFunc) (*Report, error) {
	var progress ProgressFunc
	if len(onProgress) > 0 {
		progress = onProgress[0]
	}

	start := time.Now()

	hosts, err := ExpandTargets(cfg.Targets)
	if err != nil {
		return nil, err
	}

	ports := cfg.Ports
	if len(ports) == 0 {
		ports = resolvePortPreset(cfg.PortPreset)
	}

	portsPerHost := len(ports) + len(cfg.UDPPorts)
	portsTotal := len(hosts) * portsPerHost

	var hostsDone, portsDone, warnings, criticals atomic.Int64

	emit := func() {
		if progress == nil {
			return
		}
		progress(ProgressSnapshot{
			HostsDone:  int(hostsDone.Load()),
			HostsTotal: len(hosts),
			PortsDone:  int(portsDone.Load()),
			PortsTotal: portsTotal,
			Warnings:   int(warnings.Load()),
			Criticals:  int(criticals.Load()),
			Elapsed:    time.Since(start),
		})
	}

	aliveMap := map[string]bool{}
	if cfg.SkipDiscovery {
		for _, h := range hosts {
			aliveMap[h] = true
		}
	} else {
		aliveMap = DiscoverHosts(ctx, hosts, cfg.Workers, cfg.ConnectTimeout)
	}
	emit()

	report := &Report{StartedAt: start}

	for _, h := range hosts {
		select {
		case <-ctx.Done():
			report.Duration = time.Since(start)
			report.Summarize()
			return report, ctx.Err()
		default:
		}

		hostResult := HostResult{Host: h, Alive: aliveMap[h]}

		if cfg.DoDNS {
			if dnsInfo, err := InspectDNS(ctx, h, cfg.DNSTimeout); err == nil {
				hostResult.DNS = dnsInfo
			} else {
				log.Printf("dns lookup for %s: %v", h, err)
			}
		}

		if hostResult.Alive || cfg.SkipDiscovery {
			scanHosts := []string{h}
			tcpResults := ScanTCP(ctx, scanHosts, ports, cfg.Workers, cfg.ConnectTimeout, func(PortResult) {
				portsDone.Add(1)
				emit()
			})

			for i := range tcpResults {
				before := len(tcpResults[i].Findings)
				enrichPortResult(ctx, &tcpResults[i], cfg)
				countNewFindings(tcpResults[i].Findings[before:], &warnings, &criticals)
				emit()
			}
			hostResult.Ports = append(hostResult.Ports, tcpResults...)

			if len(cfg.UDPPorts) > 0 {
				udpResults := ScanUDP(ctx, scanHosts, cfg.UDPPorts, cfg.Workers, cfg.ConnectTimeout, func(PortResult) {
					portsDone.Add(1)
					emit()
				})
				hostResult.Ports = append(hostResult.Ports, udpResults...)
			}
		}

		report.Hosts = append(report.Hosts, hostResult)
		hostsDone.Add(1)
		emit()
	}

	report.Duration = time.Since(start)
	report.Summarize()
	emit()
	return report, nil
}

// countNewFindings tallies newly-added findings by severity into the
// running atomic counters, used so the live dashboard's warning/
// critical counts track the report as it's built rather than only
// being known once Report.Summarize() walks everything at the end.
func countNewFindings(findings []Finding, warnings, criticals *atomic.Int64) {
	for _, f := range findings {
		switch f.Severity {
		case SevWarning:
			warnings.Add(1)
		case SevCritical:
			criticals.Add(1)
		}
	}
}

// enrichPortResult adds banner/fingerprint/TLS/HTTP detail to a single
// open TCP port, mutating it in place. Only StateOpen ports are worth
// the extra round-trips — closed/filtered ports have nothing further
// to learn.
func enrichPortResult(ctx context.Context, pr *PortResult, cfg config.Config) {
	if pr.State != StateOpen {
		return
	}

	if cfg.DoBanners {
		if b, err := GrabBanner(ctx, pr.Host, pr.Port, cfg.BannerTimeout); err == nil {
			pr.Banner = b
		}
	}

	if cfg.DoFinger {
		if fp, err := FingerprintOS(ctx, pr.Host, pr.Port, cfg.ConnectTimeout); err == nil {
			pr.Fingerprint = fp
		}
	}

	if cfg.DoTLS && looksLikeTLSPort(pr.Port, pr.Banner) {
		if info, findings, err := InspectTLS(ctx, pr.Host, pr.Port, cfg.ConnectTimeout); err == nil {
			pr.TLS = info
			pr.Findings = append(pr.Findings, findings...)
		}
	}

	if cfg.DoHTTP && looksLikeHTTPPort(pr.Port, pr.Banner) {
		// Now that a TLS attempt (if any) has already run, we know for
		// certain whether the port actually speaks TLS rather than
		// guessing — use that directly instead of re-heuristicizing.
		scheme := "http"
		if pr.TLS != nil {
			scheme = "https"
		}
		if info, findings, err := InspectHTTP(ctx, scheme, pr.Host, pr.Port, cfg.ConnectTimeout, cfg.AdminPaths...); err == nil {
			pr.HTTP = info
			pr.Findings = append(pr.Findings, findings...)
		}
	}

	// Unencrypted-service-on-an-expected-encrypted-port rule (section
	// 10): a handful of ports are conventionally TLS-only; seeing plain
	// HTTP (no successful TLS handshake) on one is worth flagging.
	if isConventionallyEncryptedPort(pr.Port) && pr.TLS == nil {
		pr.Findings = append(pr.Findings, Finding{
			Severity: SevWarning,
			Rule:     "unencrypted-on-tls-port",
			Message:  "port is conventionally TLS-only but no TLS handshake succeeded",
		})
	}
}

var tlsConventionalPorts = map[int]bool{
	443: true, 8443: true, 465: true, 993: true, 995: true, 636: true, 990: true,
}

// IsConventionallyEncryptedPort reports whether port is one of the
// small set of ports conventionally reserved for TLS-wrapped
// protocols. Exported for testability (same reasoning as
// scanner.HasSPFRecord) — it's a pure lookup with no dependency on
// live scan state.
func IsConventionallyEncryptedPort(port int) bool {
	return isConventionallyEncryptedPort(port)
}

func isConventionallyEncryptedPort(port int) bool {
	return tlsConventionalPorts[port]
}

// LooksLikeTLSPort reports whether a TLS handshake is worth attempting
// on this port. Exported for testability; see looksLikeTLSPort's doc
// comment for the full heuristic rationale.
func LooksLikeTLSPort(port int, b *Banner) bool {
	return looksLikeTLSPort(port, b)
}

// looksLikeTLSPort reports whether a TLS handshake is worth attempting
// on this port. Conventional TLS ports always qualify; beyond that we
// attempt TLS on any port UNLESS the banner already positively
// identified a protocol that is definitionally never TLS-wrapped (SSH
// negotiates its own encryption at the application layer and does not
// speak TLS; FTP/SMTP's plaintext welcome banners mean the connection
// already proved itself plaintext).
//
// This intentionally errs toward attempting TLS too often rather than
// too rarely: InspectTLS fails fast and cheaply (bounded by
// ConnectTimeout) against a genuinely non-TLS port, and skipping a real
// TLS service because it happened to be on an unlisted port would mean
// missing exactly the certificate-expiry/self-signed findings this
// tool exists to surface. A non-standard HTTPS port (8444 in our own
// demo-targets, for instance) is the realistic case this guards
// against — hardcoding a fixed port list alone would silently miss it.
func looksLikeTLSPort(port int, b *Banner) bool {
	if tlsConventionalPorts[port] {
		return true
	}
	if b != nil {
		switch b.Protocol {
		case "ssh", "ftp", "smtp":
			return false
		}
	}
	return true
}

// LooksLikeHTTPPort is the exported form of looksLikeHTTPPort, for
// testability.
func LooksLikeHTTPPort(port int, b *Banner) bool {
	return looksLikeHTTPPort(port, b)
}

func looksLikeHTTPPort(port int, b *Banner) bool {
	httpPorts := map[int]bool{80: true, 443: true, 8080: true, 8443: true, 8000: true, 8888: true, 3000: true}
	if httpPorts[port] {
		return true
	}
	return b != nil && b.Protocol == "http"
}
