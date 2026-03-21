package cert_test

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"

	"github.com/travisbale/mirage/internal/cert"
)

func TestFileCertSource_LoadsRealPEM(t *testing.T) {
	dir := t.TempDir()
	hostname := "mail.attacker.com"
	certDir := filepath.Join(dir, "sites", hostname)
	if err := os.MkdirAll(certDir, 0700); err != nil {
		t.Fatal(err)
	}

	tlsCert := generateTestCert(t, hostname)
	writePEMPair(t, certDir, tlsCert)

	source := &cert.FileCertSource{BaseDir: dir}
	hello := &tls.ClientHelloInfo{ServerName: hostname}
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
	if leaf.Subject.CommonName != hostname {
		t.Errorf("CommonName: got %q, want %q", leaf.Subject.CommonName, hostname)
	}
}

func TestFileCertSource_MissDirReturnsNil(t *testing.T) {
	source := &cert.FileCertSource{BaseDir: t.TempDir()}
	hello := &tls.ClientHelloInfo{ServerName: "notconfigured.attacker.com"}
	got, err := source.GetCertificate(hello)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if got != nil {
		t.Error("expected nil cert on miss")
	}
}

func TestFileCertSource_WildcardFallback(t *testing.T) {
	dir := t.TempDir()
	certDir := filepath.Join(dir, "sites", "*.attacker.com")
	if err := os.MkdirAll(certDir, 0700); err != nil {
		t.Fatal(err)
	}
	tlsCert := generateTestCert(t, "*.attacker.com")
	writePEMPair(t, certDir, tlsCert)

	source := &cert.FileCertSource{BaseDir: dir}
	hello := &tls.ClientHelloInfo{ServerName: "mail.attacker.com"}
	got, err := source.GetCertificate(hello)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if got == nil {
		t.Fatal("expected wildcard cert fallback, got nil")
	}
}
