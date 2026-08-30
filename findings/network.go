package findings

import (
	"fmt"

	"bareport/scanner"
)

// cleartextServiceRule is a finding shape for a protocol that is
// cleartext by definition. Fires only when a real banner grab on that
// port actually confirms the protocol (see networkFindings below), not
// merely because a port number matches a convention — see telnetPort
// below for the one place bareport is honest about NOT having that
// confirmation.
type cleartextServiceRule struct {
	id          string
	severity    Severity
	title       string
	description string
	remediation string
}

var cleartextServices = map[string]cleartextServiceRule{
	"ftp": {
		id:          "NET-CLEARTEXT-FTP",
		severity:    SevLow,
		title:       "Cleartext FTP service exposed",
		description: "FTP transmits credentials and file contents without encryption by default. Anyone able to observe network traffic between a client and this service can read them.",
		remediation: "Replace with SFTP/FTPS, or restrict access to a trusted network if FTP must remain in use.",
	},
}

// telnetPort: Telnet has no standard text greeting the way SSH/FTP/SMTP
// do, so scanner/banner.go can't reliably identify it from a banner
// alone. Flagging it purely by well-known port number 23 is the most
// evidence bareport can honestly claim here — the finding text below
// says exactly that, rather than implying a confirmed protocol match.
const telnetPort = 23

// networkFindings derives findings from a single open port that aren't
// specific to TLS or HTTP: general exposure inventory (INFO, one per
// open port) plus specific cleartext-protocol findings where a banner
// genuinely proves the protocol.
func networkFindings(host string, p *scanner.PortResult) []Finding {
	if p.State != scanner.StateOpen {
		return nil
	}

	var out []Finding

	service := "unknown"
	if p.Banner != nil {
		service = p.Banner.Protocol
	}

	out = append(out, Finding{
		ID:          "NET-OPEN-PORT",
		Severity:    SevInfo,
		Title:       fmt.Sprintf("Open %s port: %d/%s", service, p.Port, p.Protocol),
		Description: "This port accepted a connection during the scan. Listed for inventory purposes — an open port is not inherently a vulnerability, but every exposed service is part of the attack surface and should be intentional.",
		Evidence:    fmt.Sprintf("%s:%d/%s responded as open; detected service: %s.", host, p.Port, p.Protocol, service),
		Target:      host,
		Port:        p.Port,
		Protocol:    p.Protocol,
		Remediation: "Confirm this service is intentionally exposed. If not, close the port or restrict access (firewall rule, bind to a private interface, etc.).",
	})

	if rule, ok := cleartextServices[service]; ok {
		out = append(out, Finding{
			ID:          rule.id,
			Severity:    rule.severity,
			Title:       rule.title,
			Description: rule.description,
			Evidence:    fmt.Sprintf("Banner grab on %s:%d identified the %s protocol.", host, p.Port, service),
			Target:      host,
			Port:        p.Port,
			Protocol:    p.Protocol,
			Remediation: rule.remediation,
		})
	}

	if p.Port == telnetPort && p.Protocol == "tcp" {
		out = append(out, Finding{
			ID:          "NET-POSSIBLE-TELNET",
			Severity:    SevMedium,
			Title:       "Possible cleartext Telnet service",
			Description: "Port 23, conventionally Telnet, is open. Telnet transmits everything — including credentials — without encryption. Bareport cannot positively confirm the protocol from a banner alone (Telnet has no standard greeting text), so this is a port-convention-based finding, not a confirmed protocol identification.",
			Evidence:    fmt.Sprintf("%s:23/tcp is open.", host),
			Target:      host,
			Port:        p.Port,
			Protocol:    p.Protocol,
			Remediation: "If this is genuinely Telnet, replace it with SSH. If it's a different service that happens to use port 23, no action needed — verify manually.",
		})
	}

	return out
}
