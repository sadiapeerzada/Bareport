package scanner

// countNewFindings and enrichPortResult are both unexported, so — per
// this project's convention of keeping true unit tests for unexported
// logic inside the package itself (see tls_internal_test.go,
// tcp_internal_test.go) rather than growing the exported surface just
// for testability — they're covered here directly.
//
// enrichPortResult in particular had the widest real gap in the
// original coverage baseline: every existing test either called the
// underlying inspectors (GrabBanner/InspectTLS/InspectHTTP) directly,
// or drove a full scan through cli.Run()/scanner.Run() against closed
// ports only (skip-discovery + an unused port), so enrichPortResult's
// StateOpen branch — the one that actually calls out to all four
// enrichers and appends their findings — was only ever hit for the
// early-return "port isn't open" case. These tests spin up real local
// listeners (mirroring tests/scanner_test.go's fixtures, but scoped
// down to just what enrichPortResult itself needs) and call it
// directly with varying cfg toggles.

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
	"sync/atomic"
	"testing"
	"time"

	"bareport/config"
)

func TestCountNewFindings_TalliesBySeverity(t *testing.T) {
	findings := []Finding{
		{Severity: SevWarning},
		{Severity: SevCritical},
		{Severity: SevWarning},
		{Severity: SevInfo}, // not counted by either counter
	}
	var warnings, criticals atomic.Int64
	countNewFindings(findings, &warnings, &criticals)

	if got := warnings.Load(); got != 2 {
		t.Errorf("expected 2 warnings, got %d", got)
	}
	if got := criticals.Load(); got != 1 {
		t.Errorf("expected 1 critical, got %d", got)
	}
}

func TestCountNewFindings_EmptySliceLeavesCountersAtZero(t *testing.T) {
	var warnings, criticals atomic.Int64
	countNewFindings(nil, &warnings, &criticals)
	if warnings.Load() != 0 || criticals.Load() != 0 {
		t.Error("expected both counters to remain zero for an empty findings slice")
	}
}

func TestCountNewFindings_AccumulatesAcrossCalls(t *testing.T) {
	var warnings, criticals atomic.Int64
	countNewFindings([]Finding{{Severity: SevCritical}}, &warnings, &criticals)
	countNewFindings([]Finding{{Severity: SevCritical}, {Severity: SevWarning}}, &warnings, &criticals)

	if got := criticals.Load(); got != 2 {
		t.Errorf("expected criticals to accumulate to 2 across calls, got %d", got)
	}
	if got := warnings.Load(); got != 1 {
		t.Errorf("expected warnings to accumulate to 1 across calls, got %d", got)
	}
}

func TestEnrichPortResult_NonOpenPort_IsANoOp(t *testing.T) {
	pr := &PortResult{State: StateClosed, Host: "127.0.0.1", Port: 1}
	cfg := config.Config{DoBanners: true, DoTLS: true, DoHTTP: true, DoFinger: true}
	enrichPortResult(context.Background(), pr, cfg)

	if pr.Banner != nil || pr.TLS != nil || pr.HTTP != nil || pr.Fingerprint != nil {
		t.Error("expected enrichPortResult to do nothing at all for a non-open port")
	}
	if len(pr.Findings) != 0 {
		t.Errorf("expected no findings for a non-open port, got %+v", pr.Findings)
	}
}

// startEnrichPlainHTTP starts a minimal plain-HTTP listener for
// enrichPortResult's HTTP-enrichment branch.
func startEnrichPlainHTTP(t *testing.T) (host string, port int, cleanup func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	h, p := splitAddr(t, ln.Addr().String())
	return h, p, func() { srv.Close() }
}

// startEnrichTLS starts a self-signed HTTPS listener on a FIXED port
// (rather than an ephemeral one) for enrichPortResult's
// TLS+HTTPS-enrichment branch. A fixed, conventional HTTP port (8443
// is in both tlsConventionalPorts and looksLikeHTTPPort's port set) is
// needed here specifically because looksLikeHTTPPort only treats an
// unbannered port as HTTP-worth-probing when the port number itself is
// conventional — banners are intentionally NOT requested in this test
// (DoBanners is left off) since a raw TLS ClientHello read as a banner
// would not reliably classify as "http" anyway.
func startEnrichTLS(t *testing.T, addr string) (host string, port int, cleanup func()) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		DNSNames:              []string{"localhost"},
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("creating cert: %v", err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Skipf("could not bind %s in this environment, skipping: %v", addr, err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	})
	srv := &http.Server{Handler: mux, TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}}}
	tlsLn := tls.NewListener(ln, srv.TLSConfig)
	go srv.Serve(tlsLn)
	h, p := splitAddr(t, ln.Addr().String())
	return h, p, func() { srv.Close() }
}

func splitAddr(t *testing.T, addr string) (string, int) {
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

func TestEnrichPortResult_PlainHTTPPort_EnrichesBannerAndHTTPOnly(t *testing.T) {
	host, port, cleanup := startEnrichPlainHTTP(t)
	defer cleanup()

	pr := &PortResult{State: StateOpen, Host: host, Port: port}
	cfg := config.Config{
		DoBanners: true, DoTLS: true, DoHTTP: true,
		ConnectTimeout: time.Second, BannerTimeout: 300 * time.Millisecond,
	}
	enrichPortResult(context.Background(), pr, cfg)

	if pr.TLS != nil {
		t.Error("expected no TLS info from a plain-HTTP listener (handshake should fail)")
	}
	if pr.HTTP == nil {
		t.Fatal("expected HTTP info to be populated")
	}
	if pr.HTTP.StatusCode != 200 {
		t.Errorf("expected status 200, got %d", pr.HTTP.StatusCode)
	}
}

func TestEnrichPortResult_TLSPort_EnrichesTLSAndHTTPSFindings(t *testing.T) {
	host, port, cleanup := startEnrichTLS(t, "127.0.0.1:8443")
	defer cleanup()

	pr := &PortResult{State: StateOpen, Host: host, Port: port}
	cfg := config.Config{
		DoTLS: true, DoHTTP: true,
		ConnectTimeout: time.Second,
	}
	enrichPortResult(context.Background(), pr, cfg)

	if pr.TLS == nil {
		t.Fatal("expected TLS info to be populated for a real TLS listener")
	}
	if !pr.TLS.SelfSigned {
		t.Error("expected the generated cert to be detected as self-signed")
	}
	if pr.HTTP == nil {
		t.Fatal("expected HTTP info to be populated (scheme should be inferred as https)")
	}
	if !hasFinding(pr.Findings, "cert-self-signed") {
		t.Errorf("expected a cert-self-signed finding to have been appended, got %+v", pr.Findings)
	}
}

func TestEnrichPortResult_ConventionalTLSPortWithoutTLS_FlagsUnencrypted(t *testing.T) {
	// 8443 is one of the small set of conventionally-TLS-only ports
	// (see tlsConventionalPorts) but stays >1024 so the test doesn't
	// need elevated privileges to bind it directly.
	ln, err := net.Listen("tcp", "127.0.0.1:8443")
	if err != nil {
		t.Skipf("could not bind 127.0.0.1:8443 in this environment, skipping: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { fmt.Fprintln(w, "ok") })
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	defer srv.Close()

	pr := &PortResult{State: StateOpen, Host: "127.0.0.1", Port: 8443}
	cfg := config.Config{DoTLS: true, ConnectTimeout: 500 * time.Millisecond}
	enrichPortResult(context.Background(), pr, cfg)

	if pr.TLS != nil {
		t.Fatal("expected no TLS info: the listener on 8443 speaks plain HTTP, not TLS")
	}
	if !hasFinding(pr.Findings, "unencrypted-on-tls-port") {
		t.Errorf("expected an unencrypted-on-tls-port finding for a plain server on a conventional TLS port, got %+v", pr.Findings)
	}
}

func TestEnrichPortResult_AllTogglesOff_AddsNoEnrichmentButStillChecksConventionalPort(t *testing.T) {
	pr := &PortResult{State: StateOpen, Host: "127.0.0.1", Port: 993} // conventional TLS port, but DoTLS is off below
	cfg := config.Config{}                                            // every Do* flag false
	enrichPortResult(context.Background(), pr, cfg)

	if pr.Banner != nil || pr.TLS != nil || pr.HTTP != nil || pr.Fingerprint != nil {
		t.Error("expected no enrichment fields populated when every Do* flag is off")
	}
	// isConventionallyEncryptedPort(993) && pr.TLS == nil still holds
	// even when DoTLS is off (we never attempted TLS at all), so the
	// finding should still fire — this is the "we never even tried"
	// case as opposed to "we tried and it failed" above.
	if !hasFinding(pr.Findings, "unencrypted-on-tls-port") {
		t.Error("expected unencrypted-on-tls-port finding to fire even when DoTLS itself is disabled, since pr.TLS is still nil")
	}
}

func hasFinding(findings []Finding, rule string) bool {
	for _, f := range findings {
		if f.Rule == rule {
			return true
		}
	}
	return false
}
