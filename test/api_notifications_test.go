package test_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/travisbale/mirage/sdk"
	"github.com/travisbale/mirage/test"
)

// TestAPI_NotificationChannelCRUD verifies that notification channels can be
// created, listed, and removed via the API.
func TestAPI_NotificationChannelCRUD(t *testing.T) {
	t.Parallel()
	harness := test.NewHarness(t)

	// Create a webhook channel.
	created, err := harness.API.CreateNotificationChannel(sdk.CreateNotificationChannelRequest{
		Type: sdk.ChannelWebhook,
		URL:  "https://example.com/hook",
	})
	if err != nil {
		t.Fatalf("CreateNotificationChannel: %v", err)
	}
	if created.ID == "" {
		t.Fatal("expected non-empty channel ID")
	}
	if created.Type != sdk.ChannelWebhook {
		t.Errorf("Type = %q, want %q", created.Type, sdk.ChannelWebhook)
	}
	if !created.Enabled {
		t.Error("expected channel to be enabled by default")
	}

	// List should include the channel.
	resp, err := harness.API.ListNotificationChannels()
	if err != nil {
		t.Fatalf("ListNotificationChannels: %v", err)
	}
	if len(resp.Channels) != 1 {
		t.Fatalf("expected 1 channel, got %d", len(resp.Channels))
	}
	if resp.Channels[0].ID != created.ID {
		t.Errorf("listed channel ID = %q, want %q", resp.Channels[0].ID, created.ID)
	}

	// Delete.
	if err := harness.API.DeleteNotificationChannel(created.ID); err != nil {
		t.Fatalf("DeleteNotificationChannel: %v", err)
	}

	resp, err = harness.API.ListNotificationChannels()
	if err != nil {
		t.Fatalf("ListNotificationChannels after delete: %v", err)
	}
	if len(resp.Channels) != 0 {
		t.Errorf("expected 0 channels after delete, got %d", len(resp.Channels))
	}
}

// TestAPI_NotificationChannelWithFilter verifies that filters are persisted.
func TestAPI_NotificationChannelWithFilter(t *testing.T) {
	t.Parallel()
	harness := test.NewHarness(t)

	created, err := harness.API.CreateNotificationChannel(sdk.CreateNotificationChannelRequest{
		Type:   sdk.ChannelSlack,
		URL:    "https://hooks.slack.com/services/T/B/xxx",
		Filter: []string{"session.completed", "session.creds_captured"},
	})
	if err != nil {
		t.Fatalf("CreateNotificationChannel: %v", err)
	}
	if len(created.Filter) != 2 {
		t.Errorf("Filter length = %d, want 2", len(created.Filter))
	}
}

// TestAPI_NotificationChannelInvalidType verifies that unknown channel types are rejected.
func TestAPI_NotificationChannelInvalidType(t *testing.T) {
	t.Parallel()
	harness := test.NewHarness(t)

	_, err := harness.API.CreateNotificationChannel(sdk.CreateNotificationChannelRequest{
		Type: "carrier_pigeon",
		URL:  "https://example.com",
	})
	if err == nil {
		t.Error("expected error for invalid channel type")
	}
}

// TestAPI_NotificationEventTypes verifies that the event-types endpoint
// returns the full set of subscribable event types.
func TestAPI_NotificationEventTypes(t *testing.T) {
	t.Parallel()
	harness := test.NewHarness(t)

	types, err := harness.API.ListNotificationEventTypes()
	if err != nil {
		t.Fatalf("ListNotificationEventTypes: %v", err)
	}

	want := sdk.AllEventTypes()
	if len(types) != len(want) {
		t.Fatalf("event type count = %d, want %d", len(types), len(want))
	}

	got := make(map[sdk.EventType]bool, len(types))
	for _, et := range types {
		got[et] = true
	}
	for _, et := range want {
		if !got[et] {
			t.Errorf("missing event type %q", et)
		}
	}
}

// TestAPI_NotificationChannelInvalidFilter verifies that unknown event types in
// the filter are rejected.
func TestAPI_NotificationChannelInvalidFilter(t *testing.T) {
	t.Parallel()
	harness := test.NewHarness(t)

	_, err := harness.API.CreateNotificationChannel(sdk.CreateNotificationChannelRequest{
		Type:   sdk.ChannelWebhook,
		URL:    "https://example.com",
		Filter: []string{"session.completed", "fake.event"},
	})
	if err == nil {
		t.Error("expected error for unknown event type in filter")
	}
}

// TestAPI_WebhookReceivesSessionEvent verifies the full notification pipeline:
// create a webhook channel → trigger a session via the victim → verify the
// webhook endpoint receives a notification with session data.
func TestAPI_WebhookReceivesSessionEvent(t *testing.T) {
	t.Parallel()
	harness := test.NewHarness(t)

	// Start a webhook receiver.
	var (
		mu       sync.Mutex
		received []map[string]any
	)
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decoding webhook payload: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		mu.Lock()
		received = append(received, payload)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(receiver.Close)

	// Create a webhook channel that receives all events.
	if _, err := harness.API.CreateNotificationChannel(sdk.CreateNotificationChannelRequest{
		Type: sdk.ChannelWebhook,
		URL:  receiver.URL,
	}); err != nil {
		t.Fatalf("CreateNotificationChannel: %v", err)
	}

	// Register an upstream handler that returns a login page.
	harness.UpstreamMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body>Login</body></html>`))
	})

	// Victim visits the phishing page → creates a session → triggers session.created.
	resp := harness.VictimGet(t, "/")
	test.DrainAndClose(resp)

	// Wait for async webhook delivery.
	deadline := time.After(3 * time.Second)
	for {
		mu.Lock()
		count := len(received)
		mu.Unlock()
		if count > 0 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for webhook notification")
		case <-time.After(50 * time.Millisecond):
		}
	}

	mu.Lock()
	defer mu.Unlock()

	// Verify the notification has expected fields.
	payload := received[0]
	eventType, _ := payload["event"].(string)
	if eventType != "session.created" {
		t.Errorf("event = %q, want %q", eventType, "session.created")
	}
	session, ok := payload["session"].(map[string]any)
	if !ok {
		t.Fatal("expected session field in webhook payload")
	}
	if session["phishlet"] != "testsite" {
		t.Errorf("phishlet = %v, want %q", session["phishlet"], "testsite")
	}
}
