package findings

import (
	"fmt"
	"strings"
	"unicode"

	"bareport/scanner"
)

// httpHeaderRule describes one security header's finding shape, driving
// a small data-table instead of five near-identical if-blocks.
type httpHeaderRule struct {
	header      string
	id          string
	severity    Severity
	title       string
	description string
	remediation string
}

var httpHeaderRules = []httpHeaderRule{
	{
		header:      "Strict-Transport-Security",
		id:          "HTTP-MISSING-HSTS",
		severity:    SevMedium,
		title:       "Missing HTTP Strict Transport Security header",
		description: "The response does not include a Strict-Transport-Security header. Without it, browsers do not enforce HTTPS-only access on their own, leaving room for a downgrade to plain HTTP on future visits (e.g. via a stripped link or a captive-portal-style interception).",
		remediation: "Send `Strict-Transport-Security: max-age=<seconds>; includeSubDomains` (add `preload` once ready for browser preload lists) on every HTTPS response.",
	},
	{
		header:      "Content-Security-Policy",
		id:          "HTTP-MISSING-CSP",
		severity:    SevMedium,
		title:       "Missing Content-Security-Policy header",
		description: "The response does not include a Content-Security-Policy header. CSP is the primary browser-enforced control against cross-site scripting and related content-injection attacks; without it, the browser applies no restriction on which scripts/styles/frames the page may load.",
		remediation: "Define a Content-Security-Policy appropriate to the application (start restrictive, e.g. `default-src 'self'`, and loosen only what's actually needed) and serve it on every response.",
	},
	{
		header:      "X-Content-Type-Options",
		id:          "HTTP-MISSING-XCTO",
		severity:    SevLow,
		title:       "Missing X-Content-Type-Options header",
		description: "The response does not include X-Content-Type-Options: nosniff. Without it, some browsers may MIME-sniff a response body and render it as a different content type than the server declared, which has historically enabled certain content-injection attacks.",
		remediation: "Send `X-Content-Type-Options: nosniff` on every response.",
	},
	{
		header:      "Referrer-Policy",
		id:          "HTTP-MISSING-REFERRER-POLICY",
		severity:    SevLow,
		title:       "Missing Referrer-Policy header",
		description: "The response does not include a Referrer-Policy header. Without one, the browser's default referrer behavior may leak full URLs (including path/query data) to third-party sites linked from this page.",
		remediation: "Send an explicit `Referrer-Policy` (e.g. `strict-origin-when-cross-origin`) rather than relying on browser defaults.",
	},
	{
		header:      "X-Frame-Options",
		id:          "HTTP-MISSING-XFO",
		severity:    SevLow,
		title:       "Missing X-Frame-Options header",
		description: "The response does not include an X-Frame-Options header (and no framing restriction was observed via CSP's frame-ancestors either). Without it, the page can potentially be embedded in a third-party frame for clickjacking-style attacks.",
		remediation: "Send `X-Frame-Options: DENY` or `SAMEORIGIN`, or a CSP `frame-ancestors` directive covering the same intent.",
	},
}

// serverHeaderDisclosure flags a Server header that discloses more
// than a bare product name — specifically, one containing a digit
// (a version number) or a "/" (the conventional product/version
// separator, e.g. "Apache/2.4.49"). A bare "Server: nginx" or an
// absent header doesn't fire this; "Apache/2.4.49 (Ubuntu) PHP/7.4.3"
// does, because that string alone tells an attacker exactly which
// CVEs to try. This reads only scanner.HTTPInfo.Server, already
// collected by every HTTP scan (scanner/http.go) — no new network
// activity for this rule.
func serverHeaderDisclosure(host string, port int, scheme string, h *scanner.HTTPInfo) *Finding {
	s := h.Server
	if s == "" {
		return nil
	}
	discloses := strings.ContainsRune(s, '/')
	if !discloses {
		for _, r := range s {
			if unicode.IsDigit(r) {
				discloses = true
				break
			}
		}
	}
	if !discloses {
		return nil
	}
	return &Finding{
		ID:          "HTTP-INFO-DISCLOSURE-SERVER-HEADER",
		Severity:    SevLow,
		Title:       "Server header discloses software version",
		Description: "The Server response header includes what appears to be specific product and/or version information. This makes it easier for an attacker to look up known vulnerabilities for the exact software version in use, without any additional probing.",
		Evidence:    fmt.Sprintf("Response from %s://%s:%d/ included Server: %q.", scheme, host, port, s),
		Target:      host,
		Port:        port,
		Protocol:    "tcp",
		Remediation: "Configure the web server/framework to send a generic Server header (or omit it entirely) rather than the specific product and version.",
	}
}

// insecureCookieFindings flags each cookie missing HttpOnly (readable
// by JavaScript, so a successful XSS can steal it directly) or, on an
// HTTPS response, missing Secure (sendable back over plain HTTP if an
// attacker can force a downgrade). Reads only scanner.HTTPInfo.Cookies,
// already parsed by net/http's own Set-Cookie parser during the HTTP
// fetch (scanner/http.go) — no new network activity, no hand-rolled
// cookie parsing.
func insecureCookieFindings(host string, port int, scheme string, h *scanner.HTTPInfo) []Finding {
	var out []Finding
	for _, c := range h.Cookies {
		missingSecure := scheme == "https" && !c.Secure
		if !c.HttpOnly || missingSecure {
			var missing []string
			if !c.HttpOnly {
				missing = append(missing, "HttpOnly")
			}
			if missingSecure {
				missing = append(missing, "Secure")
			}
			out = append(out, Finding{
				ID:          "HTTP-INSECURE-COOKIE",
				Severity:    SevMedium,
				Title:       "Cookie set without recommended security flags",
				Description: "A cookie was set without one or more of the flags that limit how it can be read or transmitted. Missing HttpOnly lets client-side JavaScript (including injected via XSS) read the cookie directly; missing Secure on an HTTPS response lets the cookie be sent over a subsequently-downgraded plain-HTTP connection.",
				Evidence:    fmt.Sprintf("Cookie %q from %s://%s:%d/ was missing: %s.", c.Name, scheme, host, port, strings.Join(missing, ", ")),
				Target:      host,
				Port:        port,
				Protocol:    "tcp",
				Remediation: "Set HttpOnly on any cookie not needed by client-side script, and Secure on every cookie served over HTTPS. Consider SameSite=Strict or Lax as well.",
			})
		}
	}
	return out
}

// httpFindings derives findings from a single port's HTTPInfo, if
// present.
func httpFindings(host string, port int, scheme string, h *scanner.HTTPInfo) []Finding {
	if h == nil {
		return nil
	}
	var out []Finding

	for _, rule := range httpHeaderRules {
		if h.SecurityHeaders[rule.header] != "" {
			continue
		}
		out = append(out, Finding{
			ID:          rule.id,
			Severity:    rule.severity,
			Title:       rule.title,
			Description: rule.description,
			Evidence:    fmt.Sprintf("Response from %s://%s:%d/ (status %d) did not include a %s header.", scheme, host, port, h.StatusCode, rule.header),
			Target:      host,
			Port:        port,
			Protocol:    "tcp",
			Remediation: rule.remediation,
		})
	}

	if len(h.DangerousOpen) > 0 {
		out = append(out, Finding{
			ID:          "HTTP-DANGEROUS-METHODS",
			Severity:    SevMedium,
			Title:       "Potentially dangerous HTTP methods accepted",
			Description: "The server responded as though it accepts one or more HTTP methods (PUT, DELETE, TRACE, CONNECT) that are rarely needed by a typical web application and, if unintentionally enabled, can expand the attack surface (e.g. unauthenticated writes, cross-site tracing).",
			Evidence:    fmt.Sprintf("Server did not return 405/501 for: %v.", h.DangerousOpen),
			Target:      host,
			Port:        port,
			Protocol:    "tcp",
			Remediation: "Restrict the web server/application framework to only the HTTP methods the application actually needs.",
		})
	}

	if rule := serverHeaderDisclosure(host, port, scheme, h); rule != nil {
		out = append(out, *rule)
	}

	out = append(out, insecureCookieFindings(host, port, scheme, h)...)

	if len(h.ExposedAdminPaths) > 0 {
		out = append(out, Finding{
			ID:          "HTTP-EXPOSED-ADMIN-ENDPOINT",
			Severity:    SevHigh,
			Title:       "Administrative endpoint reachable without authentication",
			Description: "One or more paths conventionally used for administrative interfaces responded with content and no authentication challenge (no 401/403, no WWW-Authenticate header, no redirect to a login page). An exposed, unauthenticated admin surface is a direct path to full compromise of the application.",
			Evidence:    fmt.Sprintf("%s://%s:%d/ — path(s) %s responded 200 with no authentication challenge.", scheme, host, port, strings.Join(h.ExposedAdminPaths, ", ")),
			Target:      host,
			Port:        port,
			Protocol:    "tcp",
			Remediation: "Require authentication (and ideally network-level restriction) in front of every administrative endpoint. If this path is not meant to be an admin interface, verify what's actually being served there.",
		})
	}

	if scheme == "http" && !h.HTTPSUpgrade {
		sev := SevInfo
		if port == 80 {
			// Port 80 is conventionally a service's primary web entry
			// point; a primary entry point with no upgrade path to
			// HTTPS at all is a more significant gap than an arbitrary
			// non-standard plain-HTTP port, which may well be an
			// internal/dev service never meant to be encrypted.
			sev = SevLow
		}
		out = append(out, Finding{
			ID:          "HTTP-PLAINTEXT-NO-UPGRADE",
			Severity:    sev,
			Title:       "Plain HTTP service with no HTTPS upgrade",
			Description: "This service responded over plain HTTP and did not redirect to an HTTPS equivalent. Traffic to and from it (including any credentials or session tokens) is not protected against network-level eavesdropping or tampering.",
			Evidence:    fmt.Sprintf("http://%s:%d/ returned status %d with no redirect to an https:// URL.", host, port, h.StatusCode),
			Target:      host,
			Port:        port,
			Protocol:    "tcp",
			Remediation: "Serve the application over HTTPS and redirect plain-HTTP requests to the HTTPS equivalent.",
		})
	}

	return out
}
