package findings

import (
	"fmt"
	"net"
	"strings"

	"bareport/scanner"
)

// tlsFindings derives findings from a single port's TLSInfo, if
// present. Every check here reads a field scanner/tls.go already
// populated from a real handshake — nothing is guessed.
func tlsFindings(host string, port int, tls *scanner.TLSInfo) []Finding {
	if tls == nil {
		return nil
	}
	var out []Finding

	switch {
	case tls.DaysUntilExpiry < 0:
		out = append(out, Finding{
			ID:          "TLS-EXPIRED-CERT",
			Severity:    SevCritical,
			Title:       "Expired TLS certificate",
			Description: "The TLS certificate presented by this service has already expired. Clients that enforce certificate validation will refuse to connect, and clients that don't are trusting an endpoint with no currently-valid identity guarantee.",
			Evidence:    fmt.Sprintf("Certificate for %s (issuer: %s) expired %d day(s) ago, on %s.", tls.Subject, tls.Issuer, -tls.DaysUntilExpiry, tls.NotAfter.Format("2006-01-02")),
			Target:      host,
			Port:        port,
			Protocol:    "tcp",
			Remediation: "Renew the certificate and deploy it before the current one expires. Consider automated renewal (e.g. a short-lived-certificate workflow) to prevent recurrence.",
		})

	case tls.DaysUntilExpiry < 30:
		out = append(out, Finding{
			ID:          "TLS-CERT-EXPIRING-SOON",
			Severity:    SevMedium,
			Title:       "TLS certificate expiring soon",
			Description: "The TLS certificate is still valid but will expire within 30 days. An unplanned expiry causes an outage-equivalent trust failure for every client.",
			Evidence:    fmt.Sprintf("Certificate for %s expires in %d day(s), on %s.", tls.Subject, tls.DaysUntilExpiry, tls.NotAfter.Format("2006-01-02")),
			Target:      host,
			Port:        port,
			Protocol:    "tcp",
			Remediation: "Renew the certificate ahead of the expiry date.",
		})
	}

	if tls.SelfSigned {
		out = append(out, Finding{
			ID:          "TLS-SELF-SIGNED-CERT",
			Severity:    SevMedium,
			Title:       "Self-signed TLS certificate",
			Description: "This service presents a certificate that is signed by itself rather than by a certificate authority a client would already trust. Depending on context this may be intentional (internal/dev services) or may indicate a misconfiguration on a public-facing endpoint.",
			Evidence:    fmt.Sprintf("Subject and issuer are identical (%s), and the certificate's signature verifies against its own public key.", tls.Subject),
			Target:      host,
			Port:        port,
			Protocol:    "tcp",
			Remediation: "For internal/dev use, this may be acceptable if clients are configured to trust it explicitly. For a public-facing service, issue a certificate from a trusted CA (e.g. via ACME/Let's Encrypt).",
		})
	}

	if mismatch, evidence := hostnameMismatch(host, tls); mismatch {
		out = append(out, Finding{
			ID:          "TLS-HOSTNAME-MISMATCH",
			Severity:    SevHigh,
			Title:       "Certificate hostname mismatch",
			Description: "The certificate's subject alternative names do not include the hostname used to reach this service. Clients performing standard hostname verification will reject this connection (or, if verification is disabled, lose the protection it provides).",
			Evidence:    evidence,
			Target:      host,
			Port:        port,
			Protocol:    "tcp",
			Remediation: "Issue a certificate whose SAN list includes every hostname this service is actually reached by.",
		})
	}

	return out
}

// hostnameMismatch checks whether host is covered by the certificate's
// SAN list. It intentionally does nothing (returns false, "") when the
// target is an IP address or the SAN list is empty — the underlying
// x509 data (cert.DNSNames only, see scanner/tls.go's TLSInfo.SANs) has
// no IP-SAN support in this codebase, so a mismatch verdict for an
// IP target or an empty SAN list would not be backed by real evidence.
func hostnameMismatch(host string, tls *scanner.TLSInfo) (bool, string) {
	if looksLikeIP(host) || len(tls.SANs) == 0 {
		return false, ""
	}
	for _, san := range tls.SANs {
		if matchesHostname(host, san) {
			return false, ""
		}
	}
	return true, fmt.Sprintf("Host %q is not covered by the certificate's SAN list: %s.", host, strings.Join(tls.SANs, ", "))
}

// matchesHostname implements the standard wildcard rule (RFC 6125):
// "*.example.com" matches exactly one label, e.g. "www.example.com"
// but not "a.www.example.com" and not "example.com" itself.
func matchesHostname(host, pattern string) bool {
	host = strings.ToLower(host)
	pattern = strings.ToLower(pattern)
	if host == pattern {
		return true
	}
	if !strings.HasPrefix(pattern, "*.") {
		return false
	}
	suffix := pattern[1:] // ".example.com"
	if !strings.HasSuffix(host, suffix) {
		return false
	}
	// The part before the suffix must be exactly one label (no dots),
	// per RFC 6125 — "*.example.com" must not match "a.b.example.com".
	label := strings.TrimSuffix(host, suffix)
	return label != "" && !strings.Contains(label, ".")
}

func looksLikeIP(host string) bool {
	return net.ParseIP(host) != nil
}
