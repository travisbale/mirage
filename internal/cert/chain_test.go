package cert_test

import (
	"crypto/tls"
	"errors"
	"log/slog"
	"testing"

	"github.com/travisbale/mirage/internal/cert"
)

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
