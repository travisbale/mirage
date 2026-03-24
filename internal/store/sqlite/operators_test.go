package sqlite_test

import (
	"errors"
	"testing"
	"time"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/store/sqlite"
)

func TestOperators_RoundTrip(t *testing.T) {
	s := sqlite.NewOperatorStore(openTestDB(t))

	op := &aitm.Operator{
		Name:      "alice",
		CreatedAt: time.Now().Truncate(time.Second),
	}

	if err := s.CreateOperator(op); err != nil {
		t.Fatalf("CreateOperator: %v", err)
	}

	all, err := s.ListOperators()
	if err != nil {
		t.Fatalf("ListOperators: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("expected 1 operator, got %d", len(all))
	}
	if all[0].Name != "alice" {
		t.Errorf("Name = %q, want %q", all[0].Name, "alice")
	}

	if err := s.DeleteOperator("alice"); err != nil {
		t.Fatalf("DeleteOperator: %v", err)
	}

	all, _ = s.ListOperators()
	if len(all) != 0 {
		t.Errorf("expected 0 operators after delete, got %d", len(all))
	}
}

func TestOperators_Errors(t *testing.T) {
	s := sqlite.NewOperatorStore(openTestDB(t))

	op := &aitm.Operator{Name: "alice", CreatedAt: time.Now()}
	_ = s.CreateOperator(op)

	if err := s.CreateOperator(op); !errors.Is(err, aitm.ErrConflict) {
		t.Errorf("duplicate create: got %v, want ErrConflict", err)
	}
	if err := s.DeleteOperator("missing"); !errors.Is(err, aitm.ErrNotFound) {
		t.Errorf("missing delete: got %v, want ErrNotFound", err)
	}
}

func TestInvites_ConsumeOnce(t *testing.T) {
	s := sqlite.NewOperatorStore(openTestDB(t))

	invite := &aitm.OperatorInvite{
		Token:     "test-token-abc",
		Name:      "bob",
		ExpiresAt: time.Now().Add(time.Hour),
	}

	if err := s.CreateInvite(invite); err != nil {
		t.Fatalf("CreateInvite: %v", err)
	}

	got, err := s.ConsumeInvite("test-token-abc")
	if err != nil {
		t.Fatalf("ConsumeInvite: %v", err)
	}
	if got.Name != "bob" {
		t.Errorf("Name = %q, want %q", got.Name, "bob")
	}

	// Second consume should fail — token was deleted.
	_, err = s.ConsumeInvite("test-token-abc")
	if !errors.Is(err, aitm.ErrNotFound) {
		t.Errorf("second consume: got %v, want ErrNotFound", err)
	}
}

func TestInvites_NotFound(t *testing.T) {
	s := sqlite.NewOperatorStore(openTestDB(t))

	_, err := s.ConsumeInvite("nonexistent-token")
	if !errors.Is(err, aitm.ErrNotFound) {
		t.Errorf("missing token: got %v, want ErrNotFound", err)
	}
}
