package tests

// This file extends tests/scanner_test.go with the specific edge cases
// called out in the coverage-improvement plan that weren't yet
// exercised end-to-end: a TLS handshake against a non-TLS port
// (handshake failure), a TLS cert whose SAN doesn't match the host we
// connected to (hostname mismatch, tested at the findings layer
// already in findings_test.go — here we confirm InspectTLS itself
// captures the SAN metadata needed for that check), an HTTP->HTTPS
// redirect chain (HTTPSUpgrade detection), a server that accepts a
// "dangerous" method, and a connection failure (nothing listening).

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"bareport/scanner"
)

func TestTLS_HandshakeFailure_AgainstPlainTCPPort(t *testing.T) {
	// A real listener that never speaks TLS at all — the handshake
	// itself must fail (not just time out), distinct from
	// TestBanner_DetectsFakeSSH which exercises the same fixture for
	// banner-grabbing rather than TLS.
	addr, cleanup := startTCPEcho(t)
	defer cleanup()
	host, port := splitHostPort(t, addr)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	info, findings, err := scanner.InspectTLS(ctx, host, port, time.Second)
	if err == nil {
		t.Fatalf("expected InspectTLS to fail a handshake against a plaintext SSH-banner server, got info=%+v", info)
	}
	if info != nil || findings != nil {
		t.Error("expected nil info/findings alongside a handshake error")
	}
}

func TestTLS_HandshakeFailure_NothingListening(t *testing.T) {
	// Grab an ephemeral port, then close it immediately so nothing is
	// listening there — exercises InspectTLS's dial-failure path
	// (distinct from a successful dial followed by a failed handshake,
	// tested above).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	host, port := splitHostPort(t, ln.Addr().String())
	ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, _, err = scanner.InspectTLS(ctx, host, port, 500*time.Millisecond)
	if err == nil {
		t.Fatal("expected InspectTLS to fail to dial a port nothing is listening on")
	}
}

func TestTLS_CertificateMetadata_SubjectIssuerSANsCaptured(t *testing.T) {
	addr, cleanup := startTLS(t, time.Now(), time.Now().Add(365*24*time.Hour))
	defer cleanup()
	host, port := splitHostPort(t, addr)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	info, _, err := scanner.InspectTLS(ctx, host, port, time.Second)
	if err != nil {
		t.Fatalf("InspectTLS: %v", err)
	}
	if info.Subject == "" || info.Issuer == "" {
		t.Errorf("expected non-empty Subject/Issuer, got Subject=%q Issuer=%q", info.Subject, info.Issuer)
	}
	if len(info.SANs) == 0 || info.SANs[0] != "localhost" {
		t.Errorf("expected SANs to include 'localhost', got %v", info.SANs)
	}
	if info.CipherSuite == "" {
		t.Error("expected a non-empty negotiated CipherSuite name")
	}
	if info.Version == "" {
		t.Error("expected a non-empty negotiated TLS Version name")
	}
}

// startRedirectingHTTP starts a plain-HTTP server that redirects every
// request to a second, real HTTPS listener (self-signed — fine, since
// InspectHTTP's client sets InsecureSkipVerify). The client.Do call
// inside InspectHTTP actually follows redirects, so the target must be
// genuinely reachable or the whole call fails before InspectHTTP ever
// gets to look at the recorded chain; a real second listener is the
// simplest way to exercise HTTPSUpgrade detection end-to-end.
func startRedirectingHTTP(t *testing.T) (addr string, cleanup func()) {
	t.Helper()
	httpsAddr, httpsCleanup := startTLS(t, time.Now(), time.Now().Add(24*time.Hour))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		httpsCleanup()
		t.Fatalf("listen: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://"+httpsAddr+"/upgraded", http.StatusFound)
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	return ln.Addr().String(), func() { srv.Close(); httpsCleanup() }
}

func TestHTTP_HTTPSUpgradeDetected(t *testing.T) {
	addr, cleanup := startRedirectingHTTP(t)
	defer cleanup()
	host, port := splitHostPort(t, addr)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	info, findings, err := scanner.InspectHTTP(ctx, "http", host, port, time.Second)
	if err != nil {
		t.Fatalf("InspectHTTP: %v", err)
	}
	if !info.HTTPSUpgrade {
		t.Errorf("expected HTTPSUpgrade=true given a redirect to an https:// URL, chain=%v", info.RedirectChain)
	}
	if hasRule(findings, "no-https-upgrade") {
		t.Errorf("did not expect no-https-upgrade finding once an upgrade was detected, got %+v", findings)
	}
}

func startDangerousMethodHTTP(t *testing.T) (addr string, cleanup func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Accept every method with 200 OK, including PUT/DELETE, which
		// httpFindings should flag as dangerously-open.
		w.WriteHeader(http.StatusOK)
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	return ln.Addr().String(), func() { srv.Close() }
}

func TestHTTP_DangerousMethodsAccepted(t *testing.T) {
	addr, cleanup := startDangerousMethodHTTP(t)
	defer cleanup()
	host, port := splitHostPort(t, addr)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	info, findings, err := scanner.InspectHTTP(ctx, "http", host, port, time.Second)
	if err != nil {
		t.Fatalf("InspectHTTP: %v", err)
	}
	if len(info.DangerousOpen) == 0 {
		t.Errorf("expected at least one dangerous method (PUT/DELETE) to be reported open, got AllowedMethods=%v", info.AllowedMethods)
	}
	if !hasRule(findings, "dangerous-http-methods") {
		t.Errorf("expected a dangerous-http-methods finding, got %+v", findings)
	}
}

func TestHTTP_ConnectionFailure_NothingListening(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	host, port := splitHostPort(t, ln.Addr().String())
	ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, _, err = scanner.InspectHTTP(ctx, "http", host, port, 500*time.Millisecond)
	if err == nil {
		t.Fatal("expected InspectHTTP to return an error when nothing is listening")
	}
}

func TestBanner_HTTPServer_RespondsOnlyToHEADRequest(t *testing.T) {
	// Unlike TestBanner_DetectsFakeSSH (which volunteers a banner the
	// instant the connection opens), a real HTTP server stays silent
	// until it receives a request — this exercises GrabBanner's SECOND
	// branch: send the HEAD probe, then classify the response.
	addr, cleanup := startPlainHTTP(t)
	defer cleanup()
	host, port := splitHostPort(t, addr)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	banner, err := scanner.GrabBanner(ctx, host, port, time.Second)
	if err != nil {
		t.Fatalf("GrabBanner: %v", err)
	}
	if banner.Protocol != "http" {
		t.Errorf("expected protocol http, got %q (raw=%q)", banner.Protocol, banner.Raw)
	}
}

func startSilentThenRawBytes(t *testing.T, delay time.Duration) (addr string, cleanup func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		time.Sleep(delay)
		// Deliberately no trailing newline: a real line-based read
		// would need a '\n' to complete; these raw bytes are only
		// picked up by GrabBanner's final one-shot conn.Read fallback.
		conn.Write([]byte{0x01, 0x02, 0x03, 0x04})
		time.Sleep(200 * time.Millisecond) // give the client time to read before we close
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

func TestBanner_SilentServer_FallsBackToRawHexDump(t *testing.T) {
	timeout := 200 * time.Millisecond
	// Server stays silent through both the unsolicited-banner read AND
	// the post-HEAD-request read (each bounded by `timeout`), only
	// sending raw bytes midway through the THIRD read's window —
	// landing comfortably inside it (not at either edge, to avoid
	// scheduling-jitter flakiness) and exercising GrabBanner's
	// last-resort hex-dump fallback.
	addr, cleanup := startSilentThenRawBytes(t, timeout*5/2) // 2.5x: middle of the [2x,3x] third-read window
	defer cleanup()
	host, port := splitHostPort(t, addr)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	banner, err := scanner.GrabBanner(ctx, host, port, timeout)
	if err != nil {
		t.Fatalf("GrabBanner: %v", err)
	}
	if banner.Protocol != "raw" {
		t.Errorf("expected protocol raw, got %q", banner.Protocol)
	}
	if banner.HexDump == "" {
		t.Error("expected a non-empty HexDump for the raw fallback")
	}
}

func startTotallySilent(t *testing.T) (addr string, cleanup func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Accept the connection (and read/discard the HEAD request so
		// the client's Write doesn't get an immediate RST) but never
		// send a single byte back.
		buf := make([]byte, 512)
		conn.Read(buf)
		time.Sleep(2 * time.Second)
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

func TestBanner_TotalSilence_ReturnsError(t *testing.T) {
	addr, cleanup := startTotallySilent(t)
	defer cleanup()
	host, port := splitHostPort(t, addr)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err := scanner.GrabBanner(ctx, host, port, 150*time.Millisecond)
	if err == nil {
		t.Fatal("expected GrabBanner to return an error when the server never sends any data at all")
	}
}
