package cert_test

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"

	"github.com/travisbale/mirage/internal/cert"
)

func TestSelfSignedCertSource_ProducesVerifiableChain(t *testing.T) {
	source := cert.NewSelfSignedCertSource(t.TempDir())

	hello := &tls.ClientHelloInfo{ServerName: "mail.attacker.com"}
	got, err := source.GetCertificate(hello)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if got == nil {
		t.Fatal("expected cert, got nil")
	}

	leaf, err := x509.ParseCertificate(got.Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	if len(leaf.DNSNames) == 0 || leaf.DNSNames[0] != "mail.attacker.com" {
		t.Errorf("DNSNames: got %v, want [mail.attacker.com]", leaf.DNSNames)
	}

	// Build a pool with the dev CA and verify the leaf.
	pool := x509.NewCertPool()
	pool.AddCert(source.CACert())
	if _, err := leaf.Verify(x509.VerifyOptions{
		DNSName: "mail.attacker.com",
		Roots:   pool,
	}); err != nil {
		t.Errorf("Verify: %v", err)
	}
}

func TestSelfSignedCertSource_CachesLeafCerts(t *testing.T) {
	source := cert.NewSelfSignedCertSource(t.TempDir())
	hello := &tls.ClientHelloInfo{ServerName: "mail.attacker.com"}

	first, _ := source.GetCertificate(hello)
	second, _ := source.GetCertificate(hello)
	if first != second {
		t.Error("expected same *tls.Certificate pointer on second call (cache hit)")
	}
}

func TestSelfSignedCertSource_WritesCAFile(t *testing.T) {
	dir := t.TempDir()
	source := cert.NewSelfSignedCertSource(dir)
	hello := &tls.ClientHelloInfo{ServerName: "mail.attacker.com"}
	if _, err := source.GetCertificate(hello); err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}

	caPath := filepath.Join(dir, "mirage-ca.crt")
	if _, err := os.Stat(caPath); err != nil {
		t.Errorf("CA cert file not written: %v", err)
	}
}
