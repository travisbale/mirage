package events

import "github.com/travisbale/mirage/internal/aitm"

// NoOpBus is an aitm.EventBus that discards all events.
// Useful in tests that need a bus but don't care about events.
type NoOpBus struct{}

var _ aitm.EventBus = (*NoOpBus)(nil)

func (n *NoOpBus) Publish(event aitm.Event)                                         {}
func (n *NoOpBus) Subscribe(eventType aitm.EventType) <-chan aitm.Event             { return nil }
func (n *NoOpBus) Unsubscribe(eventType aitm.EventType, ch <-chan aitm.Event)       {}
