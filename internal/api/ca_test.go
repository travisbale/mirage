package api_test

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"

	"github.com/travisbale/mirage/internal/api"
)

func TestGenerateCA_WritesFiles(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")

	if _, err := api.GenerateCA(certPath); err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	if _, err := os.Stat(certPath); err != nil {
		t.Errorf("cert file not written: %v", err)
	}
	if _, err := os.Stat(certPath + ".key"); err != nil {
		t.Errorf("key file not written: %v", err)
	}
}

func TestCA_LoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")

	original, err := api.GenerateCA(certPath)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	loaded, err := api.Load(certPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if original.Cert.SerialNumber.Cmp(loaded.Cert.SerialNumber) != 0 {
		t.Error("loaded CA serial does not match generated CA")
	}
}

func TestIssueClientCert_VerifiesAgainstCA(t *testing.T) {
	dir := t.TempDir()
	ca, err := api.GenerateCA(filepath.Join(dir, "ca.crt"))
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	certPEM, keyPEM, err := ca.IssueClientCert("operator")
	if err != nil {
		t.Fatalf("IssueClientCert: %v", err)
	}

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}

	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	if leaf.Subject.CommonName != "operator" {
		t.Errorf("CommonName: got %q, want %q", leaf.Subject.CommonName, "operator")
	}

	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     ca.CertPool(),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Errorf("client cert verification failed: %v", err)
	}
}

func TestIssueClientCert_UniqueCerts(t *testing.T) {
	dir := t.TempDir()
	ca, err := api.GenerateCA(filepath.Join(dir, "ca.crt"))
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	cert1PEM, key1PEM, _ := ca.IssueClientCert("alice")
	cert2PEM, key2PEM, _ := ca.IssueClientCert("bob")

	cert1, _ := tls.X509KeyPair(cert1PEM, key1PEM)
	cert2, _ := tls.X509KeyPair(cert2PEM, key2PEM)

	leaf1, _ := x509.ParseCertificate(cert1.Certificate[0])
	leaf2, _ := x509.ParseCertificate(cert2.Certificate[0])

	if leaf1.SerialNumber.Cmp(leaf2.SerialNumber) == 0 {
		t.Error("expected unique serials for each issued cert")
	}
	if leaf1.Subject.CommonName != "alice" {
		t.Errorf("alice CN: got %q", leaf1.Subject.CommonName)
	}
	if leaf2.Subject.CommonName != "bob" {
		t.Errorf("bob CN: got %q", leaf2.Subject.CommonName)
	}
}
