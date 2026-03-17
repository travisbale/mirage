package aitm_test

import (
	"testing"

	"github.com/travisbale/mirage/internal/aitm"
)

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
