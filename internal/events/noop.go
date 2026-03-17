package events

import "github.com/travisbale/mirage/internal/aitm"

// NoOpBus discards all events.
// Useful in tests that need a bus but don't care about events.
type NoOpBus struct{}

func (n *NoOpBus) Publish(event aitm.Event) {}

func (n *NoOpBus) Subscribe(_ aitm.EventType) <-chan aitm.Event {
	ch := make(chan aitm.Event)
	close(ch)
	return ch
}

func (n *NoOpBus) Unsubscribe(eventType aitm.EventType, ch <-chan aitm.Event) {}
