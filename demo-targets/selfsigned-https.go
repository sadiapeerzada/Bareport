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

// selfsignedHTTPSServer demonstrates section 6's self-signed-cert
// detection. The certificate is generated in-process with crypto/x509
// + crypto/ecdsa — no openssl shell-out, no external cert files —
// which is also a handy pattern to remember for the real hackathon
// build: Go can be its own tiny CA for demo/test purposes.
func main() {
	addr := flag.String("addr", ":8443", "listen address")
	flag.Parse()

	cert, err := generateSelfSignedCert("localhost", 365*24*time.Hour)
	if err != nil {
		log.Fatalf("generating self-signed cert: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "bareport demo: self-signed HTTPS target")
	})

	srv := &http.Server{
		Addr:    *addr,
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
	}

	log.Printf("selfsigned-https demo listening on %s", *addr)
	log.Fatal(srv.ListenAndServeTLS("", "")) // cert already loaded into TLSConfig
}

// generateSelfSignedCert builds an in-memory, self-signed X.509
// certificate valid for `validFor` starting now, using an ECDSA P-256
// key (fast to generate, no external key files needed).
func generateSelfSignedCert(host string, validFor time.Duration) (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generating key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generating serial: %w", err)
	}

	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: host, Organization: []string{"bareport demo"}},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(validFor),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{host},
		IsCA:                  true, // self-signed root: signs itself, hence IsCA
		BasicConstraintsValid: true,
	}

	// Self-signed: template is used as both the certificate being
	// created AND the "parent" it's signed by, with its own public key.
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("creating certificate: %w", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}, nil
}
