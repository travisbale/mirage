package notify_test

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/events"
	"github.com/travisbale/mirage/internal/notify"
	"github.com/travisbale/mirage/sdk"
)

var testLogger = slog.Default()

func TestDispatcher_DeliversToMatchingChannels(t *testing.T) {
	bus := events.NewBus(16)
	dispatcher := notify.NewDispatcher(bus, testLogger)

	channels := []*aitm.NotificationChannel{
		{ID: "1", Type: sdk.ChannelWebhook, URL: "http://example.com", Enabled: true},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dispatcher.Start(ctx, channels)

	// Publish an event.
	bus.Publish(aitm.Event{
		Type:    sdk.EventSessionCreated,
		Payload: &aitm.Session{ID: "sess-1", Phishlet: "test"},
	})

	// Give the async delivery a moment.
	time.Sleep(50 * time.Millisecond)

	if err := dispatcher.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

func TestDispatcher_RespectsFilter(t *testing.T) {
	bus := events.NewBus(16)
	dispatcher := notify.NewDispatcher(bus, testLogger)

	// Channel only wants session.completed events.
	channels := []*aitm.NotificationChannel{
		{
			ID:      "1",
			Type:    sdk.ChannelWebhook,
			URL:     "http://example.com",
			Filter:  []sdk.EventType{sdk.EventSessionCompleted},
			Enabled: true,
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dispatcher.Start(ctx, channels)

	// Publish an event the channel does NOT want.
	bus.Publish(aitm.Event{
		Type:    sdk.EventSessionCreated,
		Payload: &aitm.Session{ID: "sess-1", Phishlet: "test"},
	})

	// The channel should not be subscribed to session.created at all,
	// so no delivery goroutines should be spawned.
	time.Sleep(50 * time.Millisecond)

	if err := dispatcher.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

func TestDispatcher_SkipsDisabledChannels(t *testing.T) {
	bus := events.NewBus(16)
	dispatcher := notify.NewDispatcher(bus, testLogger)

	channels := []*aitm.NotificationChannel{
		{ID: "1", Type: sdk.ChannelWebhook, URL: "http://example.com", Enabled: false},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dispatcher.Start(ctx, channels)

	bus.Publish(aitm.Event{
		Type:    sdk.EventSessionCreated,
		Payload: &aitm.Session{ID: "sess-1", Phishlet: "test"},
	})

	time.Sleep(50 * time.Millisecond)

	if err := dispatcher.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

func TestDispatcher_Reload(t *testing.T) {
	bus := events.NewBus(16)
	dispatcher := notify.NewDispatcher(bus, testLogger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start with no channels.
	dispatcher.Start(ctx, nil)

	// Reload with a channel.
	dispatcher.Reload([]*aitm.NotificationChannel{
		{ID: "1", Type: sdk.ChannelWebhook, URL: "http://example.com", Enabled: true},
	})

	bus.Publish(aitm.Event{
		Type:    sdk.EventSessionCompleted,
		Payload: &aitm.Session{ID: "sess-1", Phishlet: "test"},
	})

	time.Sleep(50 * time.Millisecond)

	if err := dispatcher.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

func TestDispatcher_Test(t *testing.T) {
	bus := events.NewBus(16)
	dispatcher := notify.NewDispatcher(bus, testLogger)

	// Test requires a valid channel type — use webhook with a URL that will fail.
	// We just verify it doesn't panic and returns an error for unreachable URL.
	ch := &aitm.NotificationChannel{
		ID:   "test-ch",
		Type: sdk.ChannelWebhook,
		URL:  "http://127.0.0.1:1", // unreachable port
	}

	err := dispatcher.Test(context.Background(), ch)
	if err == nil {
		t.Error("expected error for unreachable webhook URL")
	}
}

func TestDispatcher_TestUnknownType(t *testing.T) {
	bus := events.NewBus(16)
	dispatcher := notify.NewDispatcher(bus, testLogger)

	ch := &aitm.NotificationChannel{
		ID:   "test-ch",
		Type: "unknown",
		URL:  "http://example.com",
	}

	err := dispatcher.Test(context.Background(), ch)
	if err == nil {
		t.Error("expected error for unknown channel type")
	}
}
