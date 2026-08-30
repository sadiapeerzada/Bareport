package scanner

// This file lives inside the scanner package itself (not tests/) so it
// can exercise tlsVersionName and isSelfSigned directly as pure,
// network-free unit tests. Both functions are already exercised
// indirectly by tests/scanner_test.go's real-handshake tests, but only
// along the single code path a real Go TLS handshake happens to take
// (TLS 1.3, and whichever self-signed/CA shape those fixtures use).
// Testing them here directly lets us exhaustively cover every branch
// (all four named TLS versions plus the "unknown" fallback, and both
// the self-signed and NOT-self-signed shapes of isSelfSigned) without
// spinning up a listener for each case.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func TestTlsVersionName_AllKnownVersionsAndUnknown(t *testing.T) {
	cases := []struct {
		version uint16
		want    string
	}{
		{tls.VersionTLS10, "TLS 1.0"},
		{tls.VersionTLS11, "TLS 1.1"},
		{tls.VersionTLS12, "TLS 1.2"},
		{tls.VersionTLS13, "TLS 1.3"},
		{0x0000, "unknown (0x0000)"},
		{0xABCD, "unknown (0xabcd)"},
	}
	for _, c := range cases {
		if got := tlsVersionName(c.version); got != c.want {
			t.Errorf("tlsVersionName(0x%04x) = %q, want %q", c.version, got, c.want)
		}
	}
}

// genCert builds a minimal self-signed x509 certificate, optionally
// signed by a separate CA key/cert to produce a genuinely
// NOT-self-signed leaf for isSelfSigned's negative case.
func genCert(t *testing.T, subject, issuer pkix.Name, signerCert *x509.Certificate, signerKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generating serial: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject,
		Issuer:                issuer,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	parent := template
	signingKey := priv
	if signerCert != nil {
		parent = signerCert
		signingKey = signerKey
	}

	der, err := x509.CreateCertificate(rand.Reader, template, parent, &priv.PublicKey, signingKey)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing certificate: %v", err)
	}
	return cert, priv
}

func TestIsSelfSigned_TrueForGenuineSelfSignedCert(t *testing.T) {
	name := pkix.Name{CommonName: "leaf.example"}
	cert, _ := genCert(t, name, name, nil, nil)
	if !isSelfSigned(cert) {
		t.Error("expected a cert signed by its own key, with matching subject/issuer, to be self-signed")
	}
}

func TestIsSelfSigned_FalseWhenIssuedByADifferentCA(t *testing.T) {
	caName := pkix.Name{CommonName: "Test CA"}
	caCert, caKey := genCert(t, caName, caName, nil, nil)

	leafName := pkix.Name{CommonName: "leaf.example"}
	leafCert, _ := genCert(t, leafName, caName, caCert, caKey)

	if isSelfSigned(leafCert) {
		t.Error("expected a cert issued by a distinct CA to NOT be reported self-signed")
	}
}

func TestIsSelfSigned_FalseWhenSubjectMatchesIssuerButSignatureDoesNotVerify(t *testing.T) {
	// Same subject/issuer name (so the cheap string check alone would
	// wrongly say "self-signed"), but actually signed by an unrelated
	// key so CheckSignatureFrom must fail. This is exactly the
	// false-positive isSelfSigned's doc comment says CheckSignatureFrom
	// guards against.
	name := pkix.Name{CommonName: "confusing.example"}
	unrelatedKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating unrelated key: %v", err)
	}
	unrelatedSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	unrelatedTemplate := &x509.Certificate{
		SerialNumber:          unrelatedSerial,
		Subject:               name,
		BasicConstraintsValid: true,
		IsCA:                  true,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
	}
	unrelatedDER, err := x509.CreateCertificate(rand.Reader, unrelatedTemplate, unrelatedTemplate, &unrelatedKey.PublicKey, unrelatedKey)
	if err != nil {
		t.Fatalf("creating unrelated signer cert: %v", err)
	}
	unrelatedCert, err := x509.ParseCertificate(unrelatedDER)
	if err != nil {
		t.Fatalf("parsing unrelated signer cert: %v", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating leaf key: %v", err)
	}
	leafSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	leafTemplate := &x509.Certificate{
		SerialNumber: leafSerial,
		Subject:      name, // same name as issuer field below
		Issuer:       name,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	// Sign with the UNRELATED key/cert, but the resulting leaf's Subject
	// still prints identically to its Issuer field (both "name"), so
	// only CheckSignatureFrom can tell these apart.
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, unrelatedCert, &leafKey.PublicKey, unrelatedKey)
	if err != nil {
		t.Fatalf("creating leaf cert: %v", err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parsing leaf cert: %v", err)
	}

	if leafCert.Subject.String() != leafCert.Issuer.String() {
		t.Skip("test setup assumption failed: subject/issuer strings must match for this case to be meaningful")
	}
	if isSelfSigned(leafCert) {
		t.Error("expected isSelfSigned to return false when the signature doesn't verify, even though subject==issuer as strings")
	}
}
