package scanner

import (
	"context"
	"net"
	"strings"
	"time"
)

// InspectDNS runs the stdlib-only DNS reconnaissance from section 8:
// forward resolution, MX records, TXT records (with SPF/DMARC presence
// checks), and reverse DNS. All lookups go through net.Resolver's
// context-aware methods so they respect ctx cancellation/timeouts
// exactly like every other scanner in this package.
//
// timeout bounds the entire set of lookups (forward, MX, TXT, DMARC
// TXT, and one reverse lookup per resolved address), the same
// convention every other scanner function in this package follows
// (GrabBanner, FingerprintOS, InspectTLS, InspectHTTP all take their
// own timeout and derive a bounded context internally rather than
// trusting the caller's ctx to already carry a deadline). Without
// this, a single unresponsive resolver — nothing exotic, just a
// network that silently drops DNS queries instead of refusing them —
// hangs InspectDNS for as long as the caller's ctx stays alive, which
// in orchestrate.go's case is only cancelled by Ctrl+C/SIGTERM and
// otherwise has no deadline at all.
//
// SPF/DMARC checks are presence checks only (does a syntactically
// SPF-shaped or DMARC-shaped TXT record exist), not full policy
// validation — parsing the full SPF mechanism grammar or DMARC tag
// syntax is a project in itself and out of scope for a recon tool.
func InspectDNS(ctx context.Context, host string, timeout time.Duration) (*DNSInfo, error) {
	dnsCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	resolver := net.DefaultResolver
	info := &DNSInfo{}

	if addrs, err := resolver.LookupHost(dnsCtx, host); err == nil {
		info.Addresses = addrs
	}

	if mxRecords, err := resolver.LookupMX(dnsCtx, host); err == nil {
		for _, mx := range mxRecords {
			info.MXRecords = append(info.MXRecords, mx.Host)
		}
	}

	if txtRecords, err := resolver.LookupTXT(dnsCtx, host); err == nil {
		info.TXTRecords = txtRecords
		info.HasSPF = HasSPFRecord(txtRecords)
	}

	// DMARC lives at a fixed subdomain, not the apex, per RFC 7489.
	if dmarcTXT, err := resolver.LookupTXT(dnsCtx, "_dmarc."+host); err == nil {
		info.HasDMARC = HasDMARCRecord(dmarcTXT)
	}

	// Reverse DNS on each resolved address, best-effort — failures here
	// are common (many hosts have no PTR record) and not an error worth
	// surfacing, just an empty result.
	for _, addr := range info.Addresses {
		if names, err := resolver.LookupAddr(dnsCtx, addr); err == nil {
			info.PTR = append(info.PTR, names...)
		}
	}

	if len(info.Addresses) == 0 {
		return info, nil // host simply didn't resolve; not treated as a hard error
	}
	return info, nil
}

// HasSPFRecord and HasDMARCRecord are deliberately split out from
// InspectDNS as pure, exported functions of a []string, rather than
// left inline in the lookup loop above. This is a testability
// boundary, not just tidiness: InspectDNS itself is not meaningfully
// unit-testable without either a real DNS query (network-dependent,
// non-deterministic in a sandboxed/CI environment, and outside what
// stdlib alone can mock — net.Resolver has no dependency-injectable
// transport in the standard library) or a hand-rolled fake resolver
// (which would just be testing the fake, not this code). The actual
// presence-detection LOGIC — does this set of TXT record strings count
// as "has SPF" / "has DMARC" — has no such problem: it's pure string
// matching, so it lives here, exported specifically so
// tests/dns_test.go (in the separate `tests` package, per this
// project's test-layout convention) can exercise it directly and
// exhaustively, while InspectDNS's live-network path is covered
// end-to-end by the integration test lab (`make integration-test`,
// via `--dns` against a resolvable target) rather than a unit test.
func HasSPFRecord(txtRecords []string) bool {
	for _, t := range txtRecords {
		if strings.HasPrefix(strings.ToLower(t), "v=spf1") {
			return true
		}
	}
	return false
}

// HasDMARCRecord reports whether txtRecords contains a DMARC policy
// record (a TXT record beginning with "v=DMARC1", case-insensitive).
// See HasSPFRecord's doc comment above for why this and HasSPFRecord
// are split out from InspectDNS as pure, independently testable
// functions.
func HasDMARCRecord(txtRecords []string) bool {
	for _, t := range txtRecords {
		if strings.HasPrefix(strings.ToLower(t), "v=dmarc1") {
			return true
		}
	}
	return false
}
