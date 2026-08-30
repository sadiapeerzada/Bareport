//go:build ignore

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"time"
)

// expiredHTTPSServer demonstrates the expiry-warning feature (section
// 6/10): identical cert-generation approach to selfsigned-https.go, but
// with NotBefore/NotAfter both set in the past so bareport's TLS
// inspector reports it as expired (a critical finding) rather than
// merely self-signed.
func main() {
	addr := flag.String("addr", ":8444", "listen address")
	flag.Parse()

	cert, err := generateExpiredCert("localhost")
	if err != nil {
		log.Fatalf("generating expired cert: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "bareport demo: expired-certificate HTTPS target")
	})

	srv := &http.Server{
		Addr:    *addr,
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
	}

	log.Printf("expired-https demo listening on %s", *addr)
	log.Fatal(srv.ListenAndServeTLS("", "")) // cert already loaded into TLSConfig
}

func generateExpiredCert(host string) (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generating key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generating serial: %w", err)
	}

	// Backdated so the cert was valid for exactly one day, two years
	// ago — comfortably, unambiguously expired.
	notBefore := time.Now().AddDate(-2, 0, 0)
	notAfter := notBefore.Add(24 * time.Hour)

	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: host, Organization: []string{"bareport demo"}},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{host},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("creating certificate: %w", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}, nil
}
