package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"time"
)

// securityHeaders is the fixed set of headers section 7 requires us to
// check for presence/absence. Keys are the canonical header names as
// net/http's Header type stores them.
var securityHeaders = []string{
	"Strict-Transport-Security",
	"X-Frame-Options",
	"Content-Security-Policy",
	"X-Content-Type-Options",
	"Referrer-Policy",
}

// dangerousMethods are HTTP methods that, if broadly accepted by a
// server that doesn't need them, expand attack surface (e.g. TRACE can
// enable cross-site tracing; PUT/DELETE left open can allow unintended
// writes). Flagged per section 7/10 when the server responds as if it
// implements them.
var dangerousMethods = []string{"PUT", "DELETE", "TRACE", "CONNECT"}

// InspectHTTP fetches the target over HTTP(S), follows redirects while
// recording the chain, and audits security headers + accepted methods.
//
// adminPaths is optional (variadic solely so every existing call site
// — scanner/orchestrate.go and the tests in tests/*.go — keeps
// compiling unchanged; a caller that never passes it gets the exact
// same behavior as before this parameter existed). When non-empty,
// each path is probed with its own GET request after the main fetch;
// a path that responds with content and no authentication challenge
// (no 401/403 status, no WWW-Authenticate header) is recorded in
// HTTPInfo.ExposedAdminPaths. This is opt-in and empty by default
// (see config.Config.AdminPaths / --admin-paths) specifically because
// an unconditional guess-common-paths probe would misfire on any
// server whose catch-all route answers every path with 200 (a common,
// legitimate SPA/framework routing pattern) — see cli.go's
// --admin-paths flag doc comment for the same rationale in the
// user-facing flag description.
//
// Why a custom http.Client per call instead of http.DefaultClient: we
// need CheckRedirect to record the chain (section 7's "redirect chain
// correctness") and a bespoke TLS config for scanning self-signed
// endpoints, so a fresh client with those overrides is clearer than
// mutating shared global state.
func InspectHTTP(ctx context.Context, scheme, host string, port int, timeout time.Duration, adminPaths ...string) (*HTTPInfo, []Finding, error) {
	url := fmt.Sprintf("%s://%s:%d/", scheme, host, port)

	var chain []string
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // audit tool: inspect first, judge trust separately (see tls.go)
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			chain = append(chain, req.URL.String())
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			return nil
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("http: building request for %s: %w", url, err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("http: fetching %s: %w", url, err)
	}
	defer resp.Body.Close()

	info := &HTTPInfo{
		StatusCode:      resp.StatusCode,
		Server:          resp.Header.Get("Server"),
		FinalURL:        resp.Request.URL.String(),
		RedirectChain:   chain,
		SecurityHeaders: map[string]string{},
	}

	for _, h := range securityHeaders {
		info.SecurityHeaders[h] = resp.Header.Get(h) // "" means missing
	}

	for _, c := range resp.Cookies() {
		info.Cookies = append(info.Cookies, CookieInfo{
			Name:     c.Name,
			Secure:   c.Secure,
			HttpOnly: c.HttpOnly,
			SameSite: sameSiteName(c.SameSite),
		})
	}

	// HTTPSUpgrade: only meaningful when we started on plain http and
	// ended up on https somewhere in the chain.
	if scheme == "http" {
		for _, step := range chain {
			if len(step) >= 5 && step[:5] == "https" {
				info.HTTPSUpgrade = true
				break
			}
		}
	}

	allowed, dangerous, mErr := enumerateMethods(ctx, client, url, timeout)
	if mErr == nil {
		info.AllowedMethods = allowed
		info.DangerousOpen = dangerous
	}

	if len(adminPaths) > 0 {
		info.ExposedAdminPaths = probeAdminPaths(ctx, client, scheme, host, port, adminPaths)
	}

	return info, httpFindings(scheme, info), nil
}

// sameSiteName renders http.SameSite as the string SARIF/JSON output
// and findings/http.go want, rather than exposing net/http's own
// int-typed enum directly on CookieInfo.
func sameSiteName(s http.SameSite) string {
	switch s {
	case http.SameSiteStrictMode:
		return "Strict"
	case http.SameSiteLaxMode:
		return "Lax"
	case http.SameSiteNoneMode:
		return "None"
	default:
		return ""
	}
}

// probeAdminPaths GETs each of paths (opt-in, see InspectHTTP's doc
// comment) and returns the subset that responded with content and no
// authentication challenge: status neither 401 nor 403, and no
// WWW-Authenticate header. This is intentionally a narrow, honest
// signal — "responded without visibly demanding authentication" — not
// a guess about whether the path is genuinely an admin panel; the
// finding text this feeds (findings/http.go) is worded to match.
func probeAdminPaths(ctx context.Context, client *http.Client, scheme, host string, port int, paths []string) []string {
	var exposed []string
	for _, p := range paths {
		if p == "" {
			continue
		}
		if p[0] != '/' {
			p = "/" + p
		}
		url := fmt.Sprintf("%s://%s:%d%s", scheme, host, port, p)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			continue
		}
		if resp.Header.Get("WWW-Authenticate") != "" {
			continue
		}
		exposed = append(exposed, p)
	}
	return exposed
}

// enumerateMethods checks GET/POST/PUT/DELETE/OPTIONS individually
// (section 7) by sending each method and treating any non-405/501
// response as "accepted". A dedicated OPTIONS request is also tried
// since a well-behaved server should report its allowed methods there
// directly via the Allow header, which we merge in if present.
func enumerateMethods(ctx context.Context, client *http.Client, url string, timeout time.Duration) ([]string, []string, error) {
	candidates := []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodOptions}
	var allowed []string

	for _, m := range candidates {
		req, err := http.NewRequestWithContext(ctx, m, url, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusMethodNotAllowed && resp.StatusCode != http.StatusNotImplemented {
			allowed = append(allowed, m)
		}
	}

	var dangerous []string
	for _, d := range dangerousMethods {
		for _, a := range allowed {
			if a == d {
				dangerous = append(dangerous, d)
			}
		}
	}

	return allowed, dangerous, nil
}

// httpFindings implements section 10's HTTP-related rules: missing
// security headers (warning), dangerous methods open (warning), and
// plain-HTTP without an upgrade to HTTPS (info — not every internal
// service needs TLS, but it's worth surfacing).
func httpFindings(scheme string, info *HTTPInfo) []Finding {
	var findings []Finding

	for _, h := range securityHeaders {
		if info.SecurityHeaders[h] == "" {
			findings = append(findings, Finding{
				Severity: SevWarning,
				Rule:     "missing-security-header",
				Message:  fmt.Sprintf("missing security header: %s", h),
			})
		}
	}

	if len(info.DangerousOpen) > 0 {
		findings = append(findings, Finding{
			Severity: SevWarning,
			Rule:     "dangerous-http-methods",
			Message:  fmt.Sprintf("potentially dangerous HTTP methods accepted: %v", info.DangerousOpen),
		})
	}

	if scheme == "http" && !info.HTTPSUpgrade {
		findings = append(findings, Finding{
			Severity: SevInfo,
			Rule:     "no-https-upgrade",
			Message:  "service is plain HTTP and does not redirect to HTTPS",
		})
	}

	return findings
}
