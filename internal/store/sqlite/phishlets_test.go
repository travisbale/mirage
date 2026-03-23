package sqlite_test

import (
	"errors"
	"testing"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/store/sqlite"
)

func TestPhishlets_ConfigUpsert(t *testing.T) {
	s := sqlite.NewPhishletStore(openTestDB(t))

	cfg := &aitm.Phishlet{
		Name:       "microsoft",
		BaseDomain: "phish.example.com",
		Enabled:    true,
	}

	if err := s.SetPhishlet(cfg); err != nil {
		t.Fatalf("SetPhishlet: %v", err)
	}
	got, err := s.GetPhishlet("microsoft")
	if err != nil {
		t.Fatalf("GetPhishlet: %v", err)
	}
	if !got.Enabled {
		t.Error("Enabled should be true")
	}

	// Upsert
	cfg.Enabled = false
	_ = s.SetPhishlet(cfg)
	got, _ = s.GetPhishlet("microsoft")
	if got.Enabled {
		t.Error("Enabled should be false after upsert")
	}

	if _, err := s.GetPhishlet("missing"); !errors.Is(err, aitm.ErrNotFound) {
		t.Errorf("missing: got %v, want ErrNotFound", err)
	}
}
