package cert_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// generateTestCert creates a minimal self-signed cert suitable for tests.
func generateTestCert(t *testing.T, hostname string) *tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hostname},
		DNSNames:     []string{hostname},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return &tlsCert
}

// writePEMPair writes fullchain.pem and privkey.pem into dir.
func writePEMPair(t *testing.T, dir string, cert *tls.Certificate) {
	t.Helper()
	chainPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	if err := os.WriteFile(filepath.Join(dir, "fullchain.pem"), chainPEM, 0600); err != nil {
		t.Fatal(err)
	}
	key := cert.PrivateKey.(*ecdsa.PrivateKey)
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(filepath.Join(dir, "privkey.pem"), keyPEM, 0600); err != nil {
		t.Fatal(err)
	}
}

type stubCertSource struct {
	cert  *tls.Certificate
	calls int
}

func (s *stubCertSource) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	s.calls++
	return s.cert, nil
}

type countingCertSource struct {
	cert   *tls.Certificate
	onCall func()
}

func (s *countingCertSource) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	s.onCall()
	return s.cert, nil
}

type errCertSource struct {
	err error
}

func (s *errCertSource) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return nil, s.err
}
