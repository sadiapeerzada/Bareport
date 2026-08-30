package findings

import (
	"fmt"
	"strings"

	"bareport/scanner"
)

// dnsFindings derives findings from a single host's DNSInfo, if
// present (only populated when --dns was passed — see scanner/dns.go).
//
// SPF/DMARC absence is only flagged when the host actually has MX
// records — i.e. it's genuinely set up to receive mail. Flagging a
// missing SPF/DMARC record on a host with no MX records at all would
// be noise, not a finding: a host that doesn't receive mail has
// nothing for SPF/DMARC to protect, so "missing" carries no evidence
// of a real gap there. This mirrors the same evidence-only discipline
// the TLS/HTTP/network rules follow.
func dnsFindings(host string, dns *scanner.DNSInfo) []Finding {
	if dns == nil || len(dns.MXRecords) == 0 {
		return nil
	}

	var out []Finding

	if !dns.HasSPF {
		out = append(out, Finding{
			ID:          "DNS-MISSING-SPF",
			Severity:    SevLow,
			Title:       "Missing SPF record",
			Description: "This domain has mail exchange (MX) records but no Sender Policy Framework (SPF) TXT record. Without SPF, receiving mail servers have no domain-authorized list of servers to check an incoming message's sender against, making it easier for a message header to convincingly spoof this domain.",
			Evidence:    fmt.Sprintf("%s has MX record(s) (%s) but no TXT record beginning with \"v=spf1\".", host, strings.Join(dns.MXRecords, ", ")),
			Target:      host,
			Remediation: "Publish an SPF TXT record listing the servers authorized to send mail for this domain, e.g. `v=spf1 include:_spf.example.com ~all`.",
		})
	}

	if !dns.HasDMARC {
		out = append(out, Finding{
			ID:          "DNS-MISSING-DMARC",
			Severity:    SevLow,
			Title:       "Missing DMARC record",
			Description: "This domain has mail exchange (MX) records but no DMARC TXT record at _dmarc.<domain>. DMARC tells receiving mail servers what to do with messages that fail SPF/DKIM checks (reject, quarantine, or allow) and, critically, lets the domain owner receive aggregate reports about spoofing attempts — without it, spoofed mail failing SPF/DKIM may still be delivered.",
			Evidence:    fmt.Sprintf("%s has MX record(s) (%s) but no v=DMARC1 TXT record at _dmarc.%s.", host, strings.Join(dns.MXRecords, ", "), host),
			Target:      host,
			Remediation: "Publish a DMARC TXT record at `_dmarc.<domain>`, e.g. `v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@example.com`, starting with `p=none` to monitor before enforcing.",
		})
	}

	return out
}
