package sqlite_test

import (
	"errors"
	"testing"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/store/sqlite"
	"github.com/travisbale/mirage/sdk"
)

func TestNotifications_RoundTrip(t *testing.T) {
	s := sqlite.NewNotificationStore(openTestDB(t))

	ch := &aitm.NotificationChannel{
		ID:         "ch-1",
		Type:       sdk.ChannelSlack,
		URL:        "https://hooks.slack.com/services/T/B/xxx",
		AuthHeader: "",
		Filter:     []sdk.EventType{sdk.EventSessionCompleted, sdk.EventCredsCaptured},
		Enabled:    true,
	}

	if err := s.CreateChannel(ch); err != nil {
		t.Fatalf("CreateChannel: %v", err)
	}

	got, err := s.GetChannel(ch.ID)
	if err != nil {
		t.Fatalf("GetChannel: %v", err)
	}
	if got.Type != sdk.ChannelSlack {
		t.Errorf("Type = %q, want %q", got.Type, sdk.ChannelSlack)
	}
	if got.URL != ch.URL {
		t.Errorf("URL = %q, want %q", got.URL, ch.URL)
	}
	if len(got.Filter) != 2 {
		t.Errorf("Filter length = %d, want 2", len(got.Filter))
	}
	if !got.Enabled {
		t.Error("expected Enabled = true")
	}

	// List
	all, err := s.ListChannels()
	if err != nil {
		t.Fatalf("ListChannels: %v", err)
	}
	if len(all) != 1 {
		t.Errorf("ListChannels: got %d, want 1", len(all))
	}

	// Delete
	if err := s.DeleteChannel(ch.ID); err != nil {
		t.Fatalf("DeleteChannel: %v", err)
	}
	if _, err := s.GetChannel(ch.ID); !errors.Is(err, aitm.ErrNotFound) {
		t.Errorf("after delete: got %v, want ErrNotFound", err)
	}
}

func TestNotifications_EmptyFilter(t *testing.T) {
	s := sqlite.NewNotificationStore(openTestDB(t))

	ch := &aitm.NotificationChannel{
		ID:      "ch-2",
		Type:    sdk.ChannelWebhook,
		URL:     "https://example.com/hook",
		Enabled: true,
	}

	if err := s.CreateChannel(ch); err != nil {
		t.Fatalf("CreateChannel: %v", err)
	}

	got, err := s.GetChannel(ch.ID)
	if err != nil {
		t.Fatalf("GetChannel: %v", err)
	}
	if len(got.Filter) != 0 {
		t.Errorf("Filter length = %d, want 0", len(got.Filter))
	}
}

func TestNotifications_Errors(t *testing.T) {
	s := sqlite.NewNotificationStore(openTestDB(t))

	ch := &aitm.NotificationChannel{ID: "ch-1", Type: sdk.ChannelWebhook, URL: "http://x", Enabled: true}
	_ = s.CreateChannel(ch)

	if err := s.CreateChannel(ch); !errors.Is(err, aitm.ErrConflict) {
		t.Errorf("duplicate create: got %v, want ErrConflict", err)
	}
	if _, err := s.GetChannel("missing"); !errors.Is(err, aitm.ErrNotFound) {
		t.Errorf("missing get: got %v, want ErrNotFound", err)
	}
	if err := s.DeleteChannel("missing"); !errors.Is(err, aitm.ErrNotFound) {
		t.Errorf("missing delete: got %v, want ErrNotFound", err)
	}
}

func TestNotifications_AuthHeaderPersisted(t *testing.T) {
	s := sqlite.NewNotificationStore(openTestDB(t))

	ch := &aitm.NotificationChannel{
		ID:         "ch-3",
		Type:       sdk.ChannelWebhook,
		URL:        "https://example.com/hook",
		AuthHeader: "Bearer secret-token",
		Enabled:    true,
	}

	if err := s.CreateChannel(ch); err != nil {
		t.Fatalf("CreateChannel: %v", err)
	}

	got, err := s.GetChannel(ch.ID)
	if err != nil {
		t.Fatalf("GetChannel: %v", err)
	}
	if got.AuthHeader != "Bearer secret-token" {
		t.Errorf("AuthHeader = %q, want %q", got.AuthHeader, "Bearer secret-token")
	}
}
