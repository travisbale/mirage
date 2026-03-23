package sqlite_test

import (
	"errors"
	"testing"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/store/sqlite"
)

func TestLures_RoundTrip(t *testing.T) {
	s := sqlite.NewLureStore(openTestDB(t))

	l := &aitm.Lure{
		ID:          "lure-1",
		Phishlet:    "microsoft",
		Path:        "/",
		RedirectURL: "https://microsoft.com",
		ParamsKey:   make([]byte, 32),
	}

	if err := s.CreateLure(l); err != nil {
		t.Fatalf("CreateLure: %v", err)
	}
	got, err := s.GetLure(l.ID)
	if err != nil {
		t.Fatalf("GetLure: %v", err)
	}
	if got.RedirectURL != l.RedirectURL {
		t.Errorf("RedirectURL: got %q, want %q", got.RedirectURL, l.RedirectURL)
	}

	got.SpoofURL = "https://spoof.com"
	if err := s.UpdateLure(got); err != nil {
		t.Fatalf("UpdateLure: %v", err)
	}

	list, _ := s.ListLures()
	if len(list) != 1 {
		t.Errorf("ListLures: got %d, want 1", len(list))
	}

	if err := s.DeleteLure(l.ID); err != nil {
		t.Fatalf("DeleteLure: %v", err)
	}
	if _, err := s.GetLure(l.ID); !errors.Is(err, aitm.ErrNotFound) {
		t.Errorf("after delete: got %v, want ErrNotFound", err)
	}
}
