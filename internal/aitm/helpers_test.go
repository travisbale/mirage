package aitm_test

import (
	"io"
	"log/slog"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/sdk"
)

// stubBus is a minimal event bus for unit tests. It records published events
// and returns no-op channels for subscriptions.
type stubBus struct {
	published []aitm.Event
}

func (b *stubBus) Publish(e aitm.Event) { b.published = append(b.published, e) }
func (b *stubBus) Subscribe(_ sdk.EventType) (<-chan aitm.Event, func()) {
	return make(chan aitm.Event), func() {}
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
