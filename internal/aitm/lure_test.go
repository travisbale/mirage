package aitm_test

import (
	"strings"
	"testing"

	"github.com/travisbale/mirage/internal/aitm"
	aesgcm "github.com/travisbale/mirage/internal/crypto/aes"
)

type aesCipher = aesgcm.Cipher

type noopInvalidator struct{}

func (noopInvalidator) InvalidateLures() {}

// stubLureStore is an in-memory lureStore for testing.
type stubLureStore struct{ lures []*aitm.Lure }

func (s *stubLureStore) CreateLure(l *aitm.Lure) error {
	s.lures = append(s.lures, l)
	return nil
}
func (s *stubLureStore) GetLure(_ string) (*aitm.Lure, error) { return nil, nil }
func (s *stubLureStore) UpdateLure(_ *aitm.Lure) error        { return nil }
func (s *stubLureStore) DeleteLure(_ string) error            { return nil }
func (s *stubLureStore) ListLures() ([]*aitm.Lure, error)     { return s.lures, nil }

func TestLureService_Create_AssignsID(t *testing.T) {
	svc := &aitm.LureService{Store: &stubLureStore{}, Invalidator: noopInvalidator{}}
	lure := &aitm.Lure{Phishlet: "microsoft"}

	if err := svc.Create(lure); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if lure.ID == "" {
		t.Fatal("expected non-empty ID after Create, got empty string")
	}
}

func TestLureService_Create_AssignsParamsKey(t *testing.T) {
	svc := &aitm.LureService{Store: &stubLureStore{}, Invalidator: noopInvalidator{}}
	lure := &aitm.Lure{Phishlet: "microsoft"}

	if err := svc.Create(lure); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if len(lure.ParamsKey) != 32 {
		t.Fatalf("expected 32-byte ParamsKey, got %d bytes", len(lure.ParamsKey))
	}
}

func TestLureService_Create_UniqueIDs(t *testing.T) {
	store := &stubLureStore{}
	svc := &aitm.LureService{Store: store, Invalidator: noopInvalidator{}}

	a := &aitm.Lure{Phishlet: "microsoft"}
	b := &aitm.Lure{Phishlet: "microsoft"}

	if err := svc.Create(a); err != nil {
		t.Fatalf("Create a: %v", err)
	}
	if err := svc.Create(b); err != nil {
		t.Fatalf("Create b: %v", err)
	}
	if a.ID == b.ID {
		t.Errorf("expected unique IDs, both got %q", a.ID)
	}
}

func TestLureService_URLWithParams_RoundTrip(t *testing.T) {
	svc := &aitm.LureService{
		Store:       &stubLureStore{},
		Invalidator: noopInvalidator{},
		Cipher:      aesCipher{},
	}
	lure := &aitm.Lure{
		Hostname: "login.phish.local",
		Path:     "/p/abc",
	}
	if err := svc.Create(lure); err != nil {
		t.Fatalf("Create: %v", err)
	}

	params := map[string]string{"email": "victim@example.com", "source": "campaign-1"}
	url, err := svc.URLWithParams(lure, 443, params)
	if err != nil {
		t.Fatalf("URLWithParams: %v", err)
	}
	if !strings.Contains(url, "?p=") {
		t.Fatalf("expected ?p= in URL, got %q", url)
	}

	// Extract the token from the URL
	token := url[strings.Index(url, "?p=")+3:]
	decrypted, err := svc.DecryptParams(lure, token)
	if err != nil {
		t.Fatalf("DecryptParams: %v", err)
	}
	if decrypted["email"] != "victim@example.com" {
		t.Errorf("email = %q, want %q", decrypted["email"], "victim@example.com")
	}
	if decrypted["source"] != "campaign-1" {
		t.Errorf("source = %q, want %q", decrypted["source"], "campaign-1")
	}
}

func TestLureService_URLWithParams_EmptyParams_NoQueryString(t *testing.T) {
	svc := &aitm.LureService{
		Store:       &stubLureStore{},
		Invalidator: noopInvalidator{},
		Cipher:      aesCipher{},
	}
	lure := &aitm.Lure{
		Hostname: "login.phish.local",
		Path:     "/p/abc",
	}
	if err := svc.Create(lure); err != nil {
		t.Fatalf("Create: %v", err)
	}

	url, err := svc.URLWithParams(lure, 443, nil)
	if err != nil {
		t.Fatalf("URLWithParams: %v", err)
	}
	if strings.Contains(url, "?p=") {
		t.Errorf("expected no ?p= for empty params, got %q", url)
	}
}

func TestLureService_URLWithParams_NonStandardPort(t *testing.T) {
	svc := &aitm.LureService{
		Store:       &stubLureStore{},
		Invalidator: noopInvalidator{},
		Cipher:      aesCipher{},
	}
	lure := &aitm.Lure{
		Hostname: "login.phish.local",
		Path:     "/p/abc",
	}
	if err := svc.Create(lure); err != nil {
		t.Fatalf("Create: %v", err)
	}

	url, err := svc.URLWithParams(lure, 8443, map[string]string{"k": "v"})
	if err != nil {
		t.Fatalf("URLWithParams: %v", err)
	}
	if !strings.HasPrefix(url, "https://login.phish.local:8443/p/abc?p=") {
		t.Errorf("expected port in URL, got %q", url)
	}
}

func TestLureService_DecryptParams_EmptyToken(t *testing.T) {
	svc := &aitm.LureService{Cipher: aesCipher{}}
	lure := &aitm.Lure{ParamsKey: make([]byte, 32)}

	params, err := svc.DecryptParams(lure, "")
	if err != nil {
		t.Fatalf("DecryptParams empty: %v", err)
	}
	if len(params) != 0 {
		t.Errorf("expected empty params for empty token, got %v", params)
	}
}

func TestLureService_DecryptParams_NoKey(t *testing.T) {
	svc := &aitm.LureService{Cipher: aesCipher{}}
	lure := &aitm.Lure{} // no ParamsKey

	params, err := svc.DecryptParams(lure, "sometoken")
	if err != nil {
		t.Fatalf("DecryptParams no key: %v", err)
	}
	if len(params) != 0 {
		t.Errorf("expected empty params when no key, got %v", params)
	}
}
