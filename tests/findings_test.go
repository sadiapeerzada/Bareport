package tests

import (
	"testing"
	"time"

	"bareport/findings"
	"bareport/scanner"
)

func findingByID(fs []findings.Finding, id string) *findings.Finding {
	for i := range fs {
		if fs[i].ID == id {
			return &fs[i]
		}
	}
	return nil
}

func TestFindings_ExpiredCert(t *testing.T) {
	r := &scanner.Report{
		Hosts: []scanner.HostResult{{
			Host: "example.com",
			Ports: []scanner.PortResult{{
				Host: "example.com", Port: 443, Protocol: "tcp", State: scanner.StateOpen,
				TLS: &scanner.TLSInfo{
					Subject: "CN=example.com", Issuer: "CN=example.com",
					NotAfter: time.Now().Add(-48 * time.Hour), DaysUntilExpiry: -2,
					SelfSigned: false,
				},
			}},
		}},
	}
	fs := findings.Analyze(r)
	f := findingByID(fs, "TLS-EXPIRED-CERT")
	if f == nil {
		t.Fatal("expected TLS-EXPIRED-CERT finding, got none")
	}
	if f.Severity != findings.SevCritical {
		t.Errorf("expected CRITICAL severity, got %s", f.Severity)
	}
	if f.Target != "example.com" || f.Port != 443 {
		t.Errorf("expected target=example.com port=443, got target=%s port=%d", f.Target, f.Port)
	}
}

func TestFindings_SelfSignedCert(t *testing.T) {
	r := &scanner.Report{
		Hosts: []scanner.HostResult{{
			Host: "127.0.0.1",
			Ports: []scanner.PortResult{{
				Host: "127.0.0.1", Port: 8443, Protocol: "tcp", State: scanner.StateOpen,
				TLS: &scanner.TLSInfo{
					Subject: "CN=localhost", Issuer: "CN=localhost",
					NotAfter: time.Now().Add(365 * 24 * time.Hour), DaysUntilExpiry: 365,
					SelfSigned: true,
				},
			}},
		}},
	}
	fs := findings.Analyze(r)
	if findingByID(fs, "TLS-SELF-SIGNED-CERT") == nil {
		t.Error("expected TLS-SELF-SIGNED-CERT finding")
	}
	if findingByID(fs, "TLS-EXPIRED-CERT") != nil {
		t.Error("did not expect TLS-EXPIRED-CERT finding on a fresh cert")
	}
}

func TestFindings_HostnameMismatch(t *testing.T) {
	r := &scanner.Report{
		Hosts: []scanner.HostResult{{
			Host: "wrong-host.example.com",
			Ports: []scanner.PortResult{{
				Host: "wrong-host.example.com", Port: 443, Protocol: "tcp", State: scanner.StateOpen,
				TLS: &scanner.TLSInfo{
					Subject: "CN=other.example.com", Issuer: "CN=some-ca",
					NotAfter: time.Now().Add(365 * 24 * time.Hour), DaysUntilExpiry: 365,
					SANs: []string{"other.example.com", "*.other.example.com"},
				},
			}},
		}},
	}
	fs := findings.Analyze(r)
	f := findingByID(fs, "TLS-HOSTNAME-MISMATCH")
	if f == nil {
		t.Fatal("expected TLS-HOSTNAME-MISMATCH finding")
	}
	if f.Severity != findings.SevHigh {
		t.Errorf("expected HIGH severity, got %s", f.Severity)
	}
}

func TestFindings_HostnameMismatch_SkippedForIP(t *testing.T) {
	r := &scanner.Report{
		Hosts: []scanner.HostResult{{
			Host: "127.0.0.1",
			Ports: []scanner.PortResult{{
				Host: "127.0.0.1", Port: 443, Protocol: "tcp", State: scanner.StateOpen,
				TLS: &scanner.TLSInfo{
					Subject:  "CN=other.example.com",
					SANs:     []string{"other.example.com"},
					NotAfter: time.Now().Add(365 * 24 * time.Hour), DaysUntilExpiry: 365,
				},
			}},
		}},
	}
	fs := findings.Analyze(r)
	if findingByID(fs, "TLS-HOSTNAME-MISMATCH") != nil {
		t.Error("did not expect a hostname-mismatch finding when target is an IP literal (no evidence basis)")
	}
}

func TestFindings_HostnameMismatch_WildcardMatches(t *testing.T) {
	r := &scanner.Report{
		Hosts: []scanner.HostResult{{
			Host: "www.example.com",
			Ports: []scanner.PortResult{{
				Host: "www.example.com", Port: 443, Protocol: "tcp", State: scanner.StateOpen,
				TLS: &scanner.TLSInfo{
					Subject:  "CN=example.com",
					SANs:     []string{"*.example.com"},
					NotAfter: time.Now().Add(365 * 24 * time.Hour), DaysUntilExpiry: 365,
				},
			}},
		}},
	}
	fs := findings.Analyze(r)
	if findingByID(fs, "TLS-HOSTNAME-MISMATCH") != nil {
		t.Error("expected *.example.com to match www.example.com (single-label wildcard)")
	}
}

func TestFindings_MissingSecurityHeaders(t *testing.T) {
	r := &scanner.Report{
		Hosts: []scanner.HostResult{{
			Host: "example.com",
			Ports: []scanner.PortResult{{
				Host: "example.com", Port: 80, Protocol: "tcp", State: scanner.StateOpen,
				HTTP: &scanner.HTTPInfo{
					StatusCode: 200,
					SecurityHeaders: map[string]string{
						"Strict-Transport-Security": "",
						"X-Frame-Options":           "SAMEORIGIN",
						"Content-Security-Policy":   "",
						"X-Content-Type-Options":    "nosniff",
						"Referrer-Policy":           "",
					},
				},
			}},
		}},
	}
	fs := findings.Analyze(r)
	if findingByID(fs, "HTTP-MISSING-HSTS") == nil {
		t.Error("expected HTTP-MISSING-HSTS finding")
	}
	if findingByID(fs, "HTTP-MISSING-CSP") == nil {
		t.Error("expected HTTP-MISSING-CSP finding")
	}
	if findingByID(fs, "HTTP-MISSING-REFERRER-POLICY") == nil {
		t.Error("expected HTTP-MISSING-REFERRER-POLICY finding")
	}
	if findingByID(fs, "HTTP-MISSING-XFO") != nil {
		t.Error("did not expect HTTP-MISSING-XFO finding since X-Frame-Options was present")
	}
	if findingByID(fs, "HTTP-MISSING-XCTO") != nil {
		t.Error("did not expect HTTP-MISSING-XCTO finding since X-Content-Type-Options was present")
	}
}

func TestFindings_ServerHeaderDisclosure(t *testing.T) {
	r := &scanner.Report{
		Hosts: []scanner.HostResult{{
			Host: "example.com",
			Ports: []scanner.PortResult{{
				Host: "example.com", Port: 80, Protocol: "tcp", State: scanner.StateOpen,
				HTTP: &scanner.HTTPInfo{
					StatusCode:      200,
					Server:          "Apache/2.4.49 (Ubuntu) PHP/7.4.3",
					SecurityHeaders: map[string]string{},
					HTTPSUpgrade:    true, // avoid also tripping plaintext-no-upgrade in this test
				},
			}},
		}},
	}
	fs := findings.Analyze(r)
	f := findingByID(fs, "HTTP-INFO-DISCLOSURE-SERVER-HEADER")
	if f == nil {
		t.Fatal("expected HTTP-INFO-DISCLOSURE-SERVER-HEADER finding, got none")
	}
	if f.Severity != findings.SevLow {
		t.Errorf("expected LOW severity, got %s", f.Severity)
	}
}

func TestFindings_ServerHeaderDisclosure_BareNameNoFinding(t *testing.T) {
	r := &scanner.Report{
		Hosts: []scanner.HostResult{{
			Host: "example.com",
			Ports: []scanner.PortResult{{
				Host: "example.com", Port: 80, Protocol: "tcp", State: scanner.StateOpen,
				HTTP: &scanner.HTTPInfo{
					StatusCode:      200,
					Server:          "nginx",
					SecurityHeaders: map[string]string{},
					HTTPSUpgrade:    true,
				},
			}},
		}},
	}
	fs := findings.Analyze(r)
	if f := findingByID(fs, "HTTP-INFO-DISCLOSURE-SERVER-HEADER"); f != nil {
		t.Error("did not expect a disclosure finding for a bare product name with no version")
	}
}

func TestFindings_InsecureCookie_MissingHttpOnlyAndSecure(t *testing.T) {
	r := &scanner.Report{
		Hosts: []scanner.HostResult{{
			Host: "example.com",
			Ports: []scanner.PortResult{{
				Host: "example.com", Port: 443, Protocol: "tcp", State: scanner.StateOpen,
				TLS: &scanner.TLSInfo{Subject: "CN=example.com", Issuer: "CN=example.com", NotAfter: time.Now().Add(365 * 24 * time.Hour)},
				HTTP: &scanner.HTTPInfo{
					StatusCode:      200,
					SecurityHeaders: map[string]string{},
					Cookies:         []scanner.CookieInfo{{Name: "session", Secure: false, HttpOnly: false}},
				},
			}},
		}},
	}
	fs := findings.Analyze(r)
	f := findingByID(fs, "HTTP-INSECURE-COOKIE")
	if f == nil {
		t.Fatal("expected HTTP-INSECURE-COOKIE finding, got none")
	}
	if f.Severity != findings.SevMedium {
		t.Errorf("expected MEDIUM severity, got %s", f.Severity)
	}
}

func TestFindings_SecureCookie_NoFinding(t *testing.T) {
	r := &scanner.Report{
		Hosts: []scanner.HostResult{{
			Host: "example.com",
			Ports: []scanner.PortResult{{
				Host: "example.com", Port: 443, Protocol: "tcp", State: scanner.StateOpen,
				TLS: &scanner.TLSInfo{Subject: "CN=example.com", Issuer: "CN=example.com", NotAfter: time.Now().Add(365 * 24 * time.Hour)},
				HTTP: &scanner.HTTPInfo{
					StatusCode:      200,
					SecurityHeaders: map[string]string{},
					Cookies:         []scanner.CookieInfo{{Name: "session", Secure: true, HttpOnly: true, SameSite: "Strict"}},
				},
			}},
		}},
	}
	fs := findings.Analyze(r)
	if f := findingByID(fs, "HTTP-INSECURE-COOKIE"); f != nil {
		t.Error("did not expect a finding for a cookie with Secure+HttpOnly set")
	}
}

func TestFindings_ExposedAdminEndpoint(t *testing.T) {
	r := &scanner.Report{
		Hosts: []scanner.HostResult{{
			Host: "example.com",
			Ports: []scanner.PortResult{{
				Host: "example.com", Port: 80, Protocol: "tcp", State: scanner.StateOpen,
				HTTP: &scanner.HTTPInfo{
					StatusCode:        200,
					SecurityHeaders:   map[string]string{},
					HTTPSUpgrade:      true,
					ExposedAdminPaths: []string{"/admin"},
				},
			}},
		}},
	}
	fs := findings.Analyze(r)
	f := findingByID(fs, "HTTP-EXPOSED-ADMIN-ENDPOINT")
	if f == nil {
		t.Fatal("expected HTTP-EXPOSED-ADMIN-ENDPOINT finding, got none")
	}
	if f.Severity != findings.SevHigh {
		t.Errorf("expected HIGH severity, got %s", f.Severity)
	}
}

func TestFindings_NoAdminPathsProbed_NoFinding(t *testing.T) {
	r := &scanner.Report{
		Hosts: []scanner.HostResult{{
			Host: "example.com",
			Ports: []scanner.PortResult{{
				Host: "example.com", Port: 80, Protocol: "tcp", State: scanner.StateOpen,
				HTTP: &scanner.HTTPInfo{
					StatusCode:      200,
					SecurityHeaders: map[string]string{},
					HTTPSUpgrade:    true,
				},
			}},
		}},
	}
	fs := findings.Analyze(r)
	if f := findingByID(fs, "HTTP-EXPOSED-ADMIN-ENDPOINT"); f != nil {
		t.Error("did not expect an admin-endpoint finding when ExposedAdminPaths is empty (opt-in probe never ran)")
	}
}

func TestFindings_DangerousHTTPMethods(t *testing.T) {
	r := &scanner.Report{
		Hosts: []scanner.HostResult{{
			Host: "example.com",
			Ports: []scanner.PortResult{{
				Host: "example.com", Port: 8080, Protocol: "tcp", State: scanner.StateOpen,
				HTTP: &scanner.HTTPInfo{
					StatusCode:      200,
					SecurityHeaders: map[string]string{},
					AllowedMethods:  []string{"GET", "PUT", "DELETE"},
					DangerousOpen:   []string{"PUT", "DELETE"},
					HTTPSUpgrade:    true, // avoid also tripping the plaintext-no-upgrade finding in this test
				},
			}},
		}},
	}
	fs := findings.Analyze(r)
	f := findingByID(fs, "HTTP-DANGEROUS-METHODS")
	if f == nil {
		t.Fatal("expected HTTP-DANGEROUS-METHODS finding, got none")
	}
	if f.Severity != findings.SevMedium {
		t.Errorf("expected MEDIUM severity, got %s", f.Severity)
	}
}

func TestFindings_PlaintextNoUpgrade_Port80IsLowSeverity(t *testing.T) {
	r := &scanner.Report{
		Hosts: []scanner.HostResult{{
			Host: "example.com",
			Ports: []scanner.PortResult{{
				Host: "example.com", Port: 80, Protocol: "tcp", State: scanner.StateOpen,
				HTTP: &scanner.HTTPInfo{
					StatusCode: 200, SecurityHeaders: map[string]string{}, HTTPSUpgrade: false,
				},
			}},
		}},
	}
	fs := findings.Analyze(r)
	f := findingByID(fs, "HTTP-PLAINTEXT-NO-UPGRADE")
	if f == nil {
		t.Fatal("expected HTTP-PLAINTEXT-NO-UPGRADE finding, got none")
	}
	if f.Severity != findings.SevLow {
		t.Errorf("expected LOW severity on port 80 specifically, got %s", f.Severity)
	}
}

func TestFindings_PlaintextNoUpgrade_NonStandardPortIsInfoSeverity(t *testing.T) {
	r := &scanner.Report{
		Hosts: []scanner.HostResult{{
			Host: "example.com",
			Ports: []scanner.PortResult{{
				Host: "example.com", Port: 8080, Protocol: "tcp", State: scanner.StateOpen,
				HTTP: &scanner.HTTPInfo{
					StatusCode: 200, SecurityHeaders: map[string]string{}, HTTPSUpgrade: false,
				},
			}},
		}},
	}
	fs := findings.Analyze(r)
	f := findingByID(fs, "HTTP-PLAINTEXT-NO-UPGRADE")
	if f == nil {
		t.Fatal("expected HTTP-PLAINTEXT-NO-UPGRADE finding, got none")
	}
	if f.Severity != findings.SevInfo {
		t.Errorf("expected INFO severity on a non-standard plain-HTTP port, got %s", f.Severity)
	}
}

func TestFindings_HTTP_NilInfo_NoFindings(t *testing.T) {
	r := &scanner.Report{
		Hosts: []scanner.HostResult{{
			Host: "example.com",
			Ports: []scanner.PortResult{{
				Host: "example.com", Port: 22, Protocol: "tcp", State: scanner.StateOpen,
				HTTP: nil,
			}},
		}},
	}
	fs := findings.Analyze(r)
	for _, f := range fs {
		if f.ID == "HTTP-MISSING-HSTS" || f.ID == "HTTP-DANGEROUS-METHODS" || f.ID == "HTTP-PLAINTEXT-NO-UPGRADE" {
			t.Errorf("did not expect any HTTP-* finding when HTTPInfo is nil, got %+v", f)
		}
	}
}

func TestFindings_OpenPortInventory(t *testing.T) {
	r := &scanner.Report{
		Hosts: []scanner.HostResult{{
			Host: "127.0.0.1",
			Ports: []scanner.PortResult{
				{Host: "127.0.0.1", Port: 22, Protocol: "tcp", State: scanner.StateOpen, Banner: &scanner.Banner{Protocol: "ssh"}},
				{Host: "127.0.0.1", Port: 9999, Protocol: "tcp", State: scanner.StateClosed},
			},
		}},
	}
	fs := findings.Analyze(r)
	count := 0
	for _, f := range fs {
		if f.ID == "NET-OPEN-PORT" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 NET-OPEN-PORT finding (only the open port), got %d", count)
	}
}

func TestFindings_DeterministicOrdering(t *testing.T) {
	r := &scanner.Report{
		Hosts: []scanner.HostResult{{
			Host: "example.com",
			Ports: []scanner.PortResult{{
				Host: "example.com", Port: 443, Protocol: "tcp", State: scanner.StateOpen,
				TLS: &scanner.TLSInfo{
					Subject: "CN=example.com", Issuer: "CN=example.com",
					NotAfter: time.Now().Add(-48 * time.Hour), DaysUntilExpiry: -2,
					SelfSigned: true,
				},
			}},
		}},
	}
	fs1 := findings.Analyze(r)
	fs2 := findings.Analyze(r)
	if len(fs1) != len(fs2) {
		t.Fatalf("non-deterministic finding count: %d vs %d", len(fs1), len(fs2))
	}
	for i := range fs1 {
		if fs1[i].ID != fs2[i].ID {
			t.Errorf("non-deterministic ordering at index %d: %s vs %s", i, fs1[i].ID, fs2[i].ID)
		}
	}
	// worst severity (CRITICAL, the expired cert) must sort first
	if fs1[0].Severity != findings.SevCritical {
		t.Errorf("expected first finding to be CRITICAL, got %s", fs1[0].Severity)
	}
}

func TestFindings_DNS_MissingSPFAndDMARC(t *testing.T) {
	r := &scanner.Report{
		Hosts: []scanner.HostResult{{
			Host: "example.com",
			DNS: &scanner.DNSInfo{
				MXRecords: []string{"mail.example.com"},
				HasSPF:    false,
				HasDMARC:  false,
			},
		}},
	}
	fs := findings.Analyze(r)
	if findingByID(fs, "DNS-MISSING-SPF") == nil {
		t.Error("expected DNS-MISSING-SPF finding when MX records exist but SPF is absent")
	}
	if findingByID(fs, "DNS-MISSING-DMARC") == nil {
		t.Error("expected DNS-MISSING-DMARC finding when MX records exist but DMARC is absent")
	}
}

func TestFindings_DNS_NoMXRecords_NoFindings(t *testing.T) {
	r := &scanner.Report{
		Hosts: []scanner.HostResult{{
			Host: "example.com",
			DNS: &scanner.DNSInfo{
				MXRecords: nil, // no mail records at all
				HasSPF:    false,
				HasDMARC:  false,
			},
		}},
	}
	fs := findings.Analyze(r)
	if findingByID(fs, "DNS-MISSING-SPF") != nil || findingByID(fs, "DNS-MISSING-DMARC") != nil {
		t.Error("did not expect SPF/DMARC findings on a host with no MX records (no evidence basis)")
	}
}

func TestFindings_DNS_PresentSPFAndDMARC_NoFindings(t *testing.T) {
	r := &scanner.Report{
		Hosts: []scanner.HostResult{{
			Host: "example.com",
			DNS: &scanner.DNSInfo{
				MXRecords: []string{"mail.example.com"},
				HasSPF:    true,
				HasDMARC:  true,
			},
		}},
	}
	fs := findings.Analyze(r)
	if findingByID(fs, "DNS-MISSING-SPF") != nil {
		t.Error("did not expect DNS-MISSING-SPF finding when SPF is present")
	}
	if findingByID(fs, "DNS-MISSING-DMARC") != nil {
		t.Error("did not expect DNS-MISSING-DMARC finding when DMARC is present")
	}
}
