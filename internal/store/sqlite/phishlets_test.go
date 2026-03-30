package sqlite_test

import (
	"errors"
	"testing"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/store/sqlite"
)

func TestPhishlets_DefinitionRoundTrip(t *testing.T) {
	s := sqlite.NewPhishletStore(openTestDB(t))

	yaml := "name: microsoft\nauthor: test\nversion: 1"

	if err := s.SavePhishlet("microsoft", yaml); err != nil {
		t.Fatalf("SavePhishlet: %v", err)
	}

	got, err := s.GetPhishlet("microsoft")
	if err != nil {
		t.Fatalf("GetPhishlet: %v", err)
	}
	if got != yaml {
		t.Errorf("GetPhishlet: got %q, want %q", got, yaml)
	}

	// Update definition
	yaml2 := "name: microsoft\nauthor: test\nversion: 2"
	if err := s.SavePhishlet("microsoft", yaml2); err != nil {
		t.Fatalf("SavePhishlet update: %v", err)
	}
	got, _ = s.GetPhishlet("microsoft")
	if got != yaml2 {
		t.Errorf("after update: got %q, want %q", got, yaml2)
	}

	if _, err := s.GetPhishlet("missing"); !errors.Is(err, aitm.ErrNotFound) {
		t.Errorf("missing: got %v, want ErrNotFound", err)
	}
}

func TestPhishlets_ConfigUpsert(t *testing.T) {
	s := sqlite.NewPhishletStore(openTestDB(t))

	// SavePhishlet first so the row exists.
	if err := s.SavePhishlet("microsoft", "name: microsoft"); err != nil {
		t.Fatalf("SavePhishlet: %v", err)
	}

	cfg := &aitm.PhishletConfig{
		Name:       "microsoft",
		BaseDomain: "phish.example.com",
		Enabled:    true,
	}

	if err := s.SetConfig(cfg); err != nil {
		t.Fatalf("SetConfig: %v", err)
	}
	got, err := s.GetConfig("microsoft")
	if err != nil {
		t.Fatalf("GetConfig: %v", err)
	}
	if !got.Enabled {
		t.Error("Enabled should be true")
	}

	// Upsert
	cfg.Enabled = false
	_ = s.SetConfig(cfg)
	got, _ = s.GetConfig("microsoft")
	if got.Enabled {
		t.Error("Enabled should be false after upsert")
	}

	// Verify SetConfig doesn't wipe the yaml column.
	yaml, _ := s.GetPhishlet("microsoft")
	if yaml != "name: microsoft" {
		t.Errorf("SetConfig wiped yaml: got %q", yaml)
	}

	if _, err := s.GetConfig("missing"); !errors.Is(err, aitm.ErrNotFound) {
		t.Errorf("missing: got %v, want ErrNotFound", err)
	}
}

func TestPhishlets_ListWithFilter(t *testing.T) {
	s := sqlite.NewPhishletStore(openTestDB(t))

	// Create two phishlets, one enabled and one disabled.
	_ = s.SavePhishlet("enabled-one", "name: enabled-one")
	_ = s.SetConfig(&aitm.PhishletConfig{Name: "enabled-one", Enabled: true})

	_ = s.SavePhishlet("disabled-one", "name: disabled-one")
	_ = s.SetConfig(&aitm.PhishletConfig{Name: "disabled-one", Enabled: false})

	// No filter — both returned.
	all, err := s.ListConfigs(aitm.PhishletFilter{})
	if err != nil {
		t.Fatalf("ListConfigs all: %v", err)
	}
	if len(all) != 2 {
		t.Errorf("ListConfigs all: got %d, want 2", len(all))
	}

	// Filter enabled only.
	enabled := true
	filtered, err := s.ListConfigs(aitm.PhishletFilter{Enabled: &enabled})
	if err != nil {
		t.Fatalf("ListConfigs enabled: %v", err)
	}
	if len(filtered) != 1 {
		t.Errorf("ListConfigs enabled: got %d, want 1", len(filtered))
	}
	if len(filtered) > 0 && filtered[0].Name != "enabled-one" {
		t.Errorf("ListConfigs enabled: got %q, want %q", filtered[0].Name, "enabled-one")
	}
}
