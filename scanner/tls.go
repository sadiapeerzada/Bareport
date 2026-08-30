package scanner

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"time"
)

// certExpiryWarnDays is the threshold (section 6/10) below which a
// certificate's remaining validity triggers a warning-level Finding.
const certExpiryWarnDays = 30

// InspectTLS performs a TLS handshake against host:port and extracts
// certificate + negotiated-session details. InsecureSkipVerify is set
// deliberately: we WANT to complete the handshake and inspect
// self-signed or otherwise "invalid" certs (that's the whole point of
// an audit tool), so we do our own validity checks manually afterward
// rather than letting crypto/tls reject the connection outright.
func InspectTLS(ctx context.Context, host string, port int, timeout time.Duration) (*TLSInfo, []Finding, error) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	dialer := &net.Dialer{}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	rawConn, err := dialer.DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return nil, nil, fmt.Errorf("tls: dialing %s: %w", addr, err)
	}
	defer rawConn.Close()

	rawConn.SetDeadline(time.Now().Add(timeout))

	tlsConn := tls.Client(rawConn, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, // intentional: we inspect untrusted/self-signed certs ourselves below
		MinVersion:         tls.VersionTLS10,
	})
	if err := tlsConn.HandshakeContext(dialCtx); err != nil {
		return nil, nil, fmt.Errorf("tls: handshake with %s: %w", addr, err)
	}
	defer tlsConn.Close()

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, nil, fmt.Errorf("tls: %s presented no certificates", addr)
	}
	cert := state.PeerCertificates[0]

	info := &TLSInfo{
		Version:         tlsVersionName(state.Version),
		CipherSuite:     tls.CipherSuiteName(state.CipherSuite),
		Subject:         cert.Subject.String(),
		Issuer:          cert.Issuer.String(),
		NotAfter:        cert.NotAfter,
		DaysUntilExpiry: int(time.Until(cert.NotAfter).Hours() / 24),
		SelfSigned:      isSelfSigned(cert),
		SANs:            cert.DNSNames,
	}

	return info, tlsFindings(info), nil
}

// tlsFindings implements the severity/warning rules from section 10
// that are specific to TLS: expired certs are critical, soon-to-expire
// certs are warnings, self-signed certs are flagged at info level (not
// automatically bad — plenty of internal/dev services use them
// legitimately — but worth surfacing).
func tlsFindings(info *TLSInfo) []Finding {
	var findings []Finding

	switch {
	case info.DaysUntilExpiry < 0:
		findings = append(findings, Finding{
			Severity: SevCritical,
			Rule:     "cert-expired",
			Message:  fmt.Sprintf("certificate expired %d day(s) ago (%s)", -info.DaysUntilExpiry, info.NotAfter.Format("2006-01-02")),
		})
	case info.DaysUntilExpiry < certExpiryWarnDays:
		findings = append(findings, Finding{
			Severity: SevWarning,
			Rule:     "cert-expiring-soon",
			Message:  fmt.Sprintf("certificate expires in %d day(s) (%s)", info.DaysUntilExpiry, info.NotAfter.Format("2006-01-02")),
		})
	}

	if info.SelfSigned {
		findings = append(findings, Finding{
			Severity: SevInfo,
			Rule:     "cert-self-signed",
			Message:  "certificate is self-signed",
		})
	}

	return findings
}

// isSelfSigned reports whether cert's issuer and subject are identical
// AND the certificate's own signature verifies against its own public
// key — the standard definition of a self-signed cert. Checking only
// subject==issuer would false-positive on some legitimately-issued
// certs with unusual naming, so we confirm with CheckSignatureFrom.
func isSelfSigned(cert *x509.Certificate) bool {
	if cert.Subject.String() != cert.Issuer.String() {
		return false
	}
	return cert.CheckSignatureFrom(cert) == nil
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown (0x%04x)", v)
	}
}
