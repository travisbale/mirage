package cert_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/travisbale/mirage/internal/cert"
)

// ── FileCertSource ────────────────────────────────────────────────────────────

func TestFileCertSource_LoadsRealPEM(t *testing.T) {
	dir := t.TempDir()
	hostname := "mail.attacker.com"
	certDir := filepath.Join(dir, "sites", hostname)
	if err := os.MkdirAll(certDir, 0700); err != nil {
		t.Fatal(err)
	}

	tlsCert := generateTestCert(t, hostname)
	writePEMPair(t, certDir, tlsCert)

	source := cert.NewFileCertSource(dir)
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
	source := cert.NewFileCertSource(t.TempDir())
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

	source := cert.NewFileCertSource(dir)
	hello := &tls.ClientHelloInfo{ServerName: "mail.attacker.com"}
	got, err := source.GetCertificate(hello)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if got == nil {
		t.Fatal("expected wildcard cert fallback, got nil")
	}
}

// ── SelfSignedCertSource ──────────────────────────────────────────────────────

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

// ── ChainedCertSource ─────────────────────────────────────────────────────────

func TestChainedCertSource_FallsThroughToNextOnMiss(t *testing.T) {
	stubA := &stubCertSource{cert: nil}
	stubB := &stubCertSource{cert: generateTestCert(t, "mail.attacker.com")}

	chain := cert.NewChainedCertSource(slog.Default(), stubA, stubB)
	hello := &tls.ClientHelloInfo{ServerName: "mail.attacker.com"}
	got, err := chain.GetCertificate(hello)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if got == nil {
		t.Fatal("expected cert from stubB")
	}
	if stubA.calls != 1 {
		t.Errorf("stubA calls: got %d, want 1", stubA.calls)
	}
	if stubB.calls != 1 {
		t.Errorf("stubB calls: got %d, want 1", stubB.calls)
	}
}

func TestChainedCertSource_CachesOnHit(t *testing.T) {
	calls := 0
	counting := &countingCertSource{
		cert:   generateTestCert(t, "mail.attacker.com"),
		onCall: func() { calls++ },
	}
	chain := cert.NewChainedCertSource(slog.Default(), counting)
	hello := &tls.ClientHelloInfo{ServerName: "mail.attacker.com"}

	chain.GetCertificate(hello)
	chain.GetCertificate(hello)
	if calls != 1 {
		t.Errorf("source calls: got %d, want 1 (second should hit cache)", calls)
	}
}

func TestChainedCertSource_StopsChainOnError(t *testing.T) {
	errSource := &errCertSource{err: errors.New("acme rate limit")}
	neverSource := &stubCertSource{cert: generateTestCert(t, "x.com")}

	chain := cert.NewChainedCertSource(slog.Default(), errSource, neverSource)
	hello := &tls.ClientHelloInfo{ServerName: "x.com"}
	_, err := chain.GetCertificate(hello)
	if err == nil {
		t.Error("expected error, got nil")
	}
	if neverSource.calls != 0 {
		t.Errorf("neverSource should not have been called, got %d calls", neverSource.calls)
	}
}

func TestChainedCertSource_NoSNIReturnsError(t *testing.T) {
	chain := cert.NewChainedCertSource(slog.Default(), &stubCertSource{})
	hello := &tls.ClientHelloInfo{ServerName: ""}
	_, err := chain.GetCertificate(hello)
	if err == nil {
		t.Error("expected error for empty SNI")
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

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
