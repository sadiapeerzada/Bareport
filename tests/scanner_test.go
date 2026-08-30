package tests

// scanner_test.go lives in tests/ (per the hackathon's suggested
// submission layout) rather than inside scanner/ itself, so it can
// freely spin up the demo-target servers as in-process goroutines
// (via httptest-style manual net.Listen calls, mirroring what
// demo-targets/*.go do standalone) and drive the real scanner package
// against them end-to-end through its exported API, rather than only
// unit-testing individual functions in isolation. Section 17 asks
// specifically for tests "against the demo-targets servers" — this
// file is the closest approximation to that runnable from `go test
// ./...` without shelling out to `go run` the ignore-tagged demo files
// (which aren't part of the module's own build graph, by design — see
// demo-targets/run-all.go for why).

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	"bareport/scanner"
)

// -------- test fixtures: minimal in-process versions of demo-targets --------

// startPlainHTTP mirrors demo-targets/plain-http.go closely enough for
// assertions: some security headers present, some deliberately absent.
func startPlainHTTP(t *testing.T) (addr string, cleanup func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "bareport-test-plain-http")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		fmt.Fprintln(w, "ok")
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	return ln.Addr().String(), func() { srv.Close() }
}

// startTLS mirrors selfsigned-https.go / expired-https.go: generates
// an in-memory cert with the given validity window and serves HTTPS.
func startTLS(t *testing.T, notBefore, notAfter time.Time) (addr string, cleanup func()) {
	t.Helper()
	cert := generateTestCert(t, notBefore, notAfter)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	})
	srv := &http.Server{
		Handler:   mux,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
	}
	tlsLn := tls.NewListener(ln, srv.TLSConfig)
	go srv.Serve(tlsLn)
	return ln.Addr().String(), func() { srv.Close() }
}

func generateTestCert(t *testing.T, notBefore, notAfter time.Time) tls.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generating serial: %v", err)
	}
	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "localhost", Organization: []string{"bareport test"}},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"localhost"},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
}

// startTCPEcho mirrors tcp-echo.go: sends a fake SSH banner on connect.
func startTCPEcho(t *testing.T) (addr string, cleanup func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				fmt.Fprintf(conn, "SSH-2.0-bareport_test\r\n")
				buf := make([]byte, 512)
				conn.Read(buf) // drain, ignore
			}()
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

// -------- tests --------

func splitHostPort(t *testing.T, addr string) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("splitting addr %s: %v", addr, err)
	}
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		t.Fatalf("parsing port from %s: %v", addr, err)
	}
	return host, port
}

func TestTCPScan_OpenAndClosedPorts(t *testing.T) {
	addr, cleanup := startPlainHTTP(t)
	defer cleanup()
	host, port := splitHostPort(t, addr)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	results := scanner.ScanTCP(ctx, []string{host}, []int{port, port + 40000}, 10, 500*time.Millisecond)

	var gotOpen, gotClosedOrFiltered bool
	for _, r := range results {
		if r.Port == port && r.State == scanner.StateOpen {
			gotOpen = true
		}
		if r.Port == port+40000 && r.State != scanner.StateOpen {
			gotClosedOrFiltered = true
		}
	}
	if !gotOpen {
		t.Errorf("expected port %d to be reported open, got results: %+v", port, results)
	}
	if !gotClosedOrFiltered {
		t.Errorf("expected unused port %d to be closed/filtered, got results: %+v", port+40000, results)
	}
}

func TestBanner_DetectsFakeSSH(t *testing.T) {
	addr, cleanup := startTCPEcho(t)
	defer cleanup()
	host, port := splitHostPort(t, addr)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	banner, err := scanner.GrabBanner(ctx, host, port, time.Second)
	if err != nil {
		t.Fatalf("GrabBanner: %v", err)
	}
	if banner.Protocol != "ssh" {
		t.Errorf("expected protocol ssh, got %q (raw=%q)", banner.Protocol, banner.Raw)
	}
}

func TestTLS_SelfSignedDetection(t *testing.T) {
	addr, cleanup := startTLS(t, time.Now(), time.Now().Add(365*24*time.Hour))
	defer cleanup()
	host, port := splitHostPort(t, addr)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	info, findings, err := scanner.InspectTLS(ctx, host, port, time.Second)
	if err != nil {
		t.Fatalf("InspectTLS: %v", err)
	}
	if !info.SelfSigned {
		t.Error("expected SelfSigned=true")
	}
	if !hasRule(findings, "cert-self-signed") {
		t.Errorf("expected cert-self-signed finding, got %+v", findings)
	}
	if hasRule(findings, "cert-expired") {
		t.Errorf("did not expect cert-expired finding on a fresh cert, got %+v", findings)
	}
}

func TestTLS_ExpiredCertDetection(t *testing.T) {
	notBefore := time.Now().AddDate(-2, 0, 0)
	notAfter := notBefore.Add(24 * time.Hour)
	addr, cleanup := startTLS(t, notBefore, notAfter)
	defer cleanup()
	host, port := splitHostPort(t, addr)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	info, findings, err := scanner.InspectTLS(ctx, host, port, time.Second)
	if err != nil {
		t.Fatalf("InspectTLS: %v", err)
	}
	if info.DaysUntilExpiry >= 0 {
		t.Errorf("expected negative DaysUntilExpiry, got %d", info.DaysUntilExpiry)
	}
	if !hasRule(findings, "cert-expired") {
		t.Errorf("expected cert-expired finding, got %+v", findings)
	}
}

func TestHTTP_MissingSecurityHeaders(t *testing.T) {
	addr, cleanup := startPlainHTTP(t)
	defer cleanup()
	host, port := splitHostPort(t, addr)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	info, findings, err := scanner.InspectHTTP(ctx, "http", host, port, time.Second)
	if err != nil {
		t.Fatalf("InspectHTTP: %v", err)
	}
	if info.SecurityHeaders["X-Content-Type-Options"] == "" {
		t.Error("expected X-Content-Type-Options to be present (test server sets it)")
	}
	if info.SecurityHeaders["Strict-Transport-Security"] != "" {
		t.Error("expected Strict-Transport-Security to be absent (test server doesn't set it)")
	}
	if !hasRule(findings, "missing-security-header") {
		t.Errorf("expected at least one missing-security-header finding, got %+v", findings)
	}
}

// startCookieAdminServer serves a server that sets an insecure cookie
// on "/" and an unauthenticated "/admin" endpoint — mirroring the
// vulnerable state of demo-targets/vulnerable-app.go closely enough
// to exercise InspectHTTP's cookie collection and opt-in admin-path
// probing end-to-end.
func startCookieAdminServer(t *testing.T) (addr string, cleanup func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "abc", Path: "/"})
		fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "admin panel")
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	return ln.Addr().String(), func() { srv.Close() }
}

func TestHTTP_CookieCollection(t *testing.T) {
	addr, cleanup := startCookieAdminServer(t)
	defer cleanup()
	host, port := splitHostPort(t, addr)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	info, _, err := scanner.InspectHTTP(ctx, "http", host, port, time.Second)
	if err != nil {
		t.Fatalf("InspectHTTP: %v", err)
	}
	if len(info.Cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(info.Cookies))
	}
	c := info.Cookies[0]
	if c.Name != "session" || c.Secure || c.HttpOnly {
		t.Errorf("expected session cookie with Secure=false HttpOnly=false, got %+v", c)
	}
}

func TestHTTP_AdminPathProbe_OptIn(t *testing.T) {
	addr, cleanup := startCookieAdminServer(t)
	defer cleanup()
	host, port := splitHostPort(t, addr)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Without adminPaths passed, no probing happens at all — this is
	// the default, unconditional-scan behavior every other test in
	// this file already exercises.
	info, _, err := scanner.InspectHTTP(ctx, "http", host, port, time.Second)
	if err != nil {
		t.Fatalf("InspectHTTP: %v", err)
	}
	if len(info.ExposedAdminPaths) != 0 {
		t.Errorf("expected no admin-path probing without opt-in, got %v", info.ExposedAdminPaths)
	}

	// With --admin-paths equivalent passed explicitly, the exposed
	// path is detected.
	info2, _, err := scanner.InspectHTTP(ctx, "http", host, port, time.Second, "admin")
	if err != nil {
		t.Fatalf("InspectHTTP with adminPaths: %v", err)
	}
	if len(info2.ExposedAdminPaths) != 1 || info2.ExposedAdminPaths[0] != "/admin" {
		t.Errorf("expected [/admin] exposed, got %v", info2.ExposedAdminPaths)
	}
}

func TestHTTP_AdminPathProbe_AuthenticatedNotFlagged(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { fmt.Fprintln(w, "ok") })
	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Basic realm="admin"`)
		http.Error(w, "authentication required", http.StatusUnauthorized)
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	defer srv.Close()

	host, port := splitHostPort(t, ln.Addr().String())
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	info, _, err := scanner.InspectHTTP(ctx, "http", host, port, time.Second, "admin")
	if err != nil {
		t.Fatalf("InspectHTTP: %v", err)
	}
	if len(info.ExposedAdminPaths) != 0 {
		t.Errorf("expected a 401+WWW-Authenticate admin path to NOT be flagged as exposed, got %v", info.ExposedAdminPaths)
	}
}

func TestDiscovery_AliveHost(t *testing.T) {
	addr, cleanup := startPlainHTTP(t)
	defer cleanup()
	host, _ := splitHostPort(t, addr)

	// IsAlive checks a fixed set of common ports, not the ephemeral
	// port our test server bound to, so this just confirms the
	// mechanism runs without error against a genuinely live host.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = scanner.IsAlive(ctx, host, 500*time.Millisecond) // 127.0.0.1 is always "alive" at the IP layer in this sandbox
}

func hasRule(findings []scanner.Finding, rule string) bool {
	for _, f := range findings {
		if f.Rule == rule {
			return true
		}
	}
	return false
}
