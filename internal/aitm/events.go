package aitm

import (
	"time"

	"github.com/travisbale/mirage/sdk"
)

// Event is a domain event published to the bus.
type Event struct {
	Type       sdk.EventType
	OccurredAt time.Time
	Payload    any
}

// eventBus is the publish/subscribe interface for decoupling components.
// Implementations must be safe for concurrent use.
// Publish must never block — if a subscriber's channel is full, the event is dropped.
type eventBus interface {
	Publish(event Event)
	Subscribe(eventType sdk.EventType) <-chan Event
	Unsubscribe(eventType sdk.EventType, ch <-chan Event)
}

// SubscribeFunc subscribes to eventType on bus and starts a goroutine that
// calls fn for each received event. The goroutine exits when the subscription
// channel is closed (i.e., when Unsubscribe is called for the returned channel).
//
// fn is called sequentially — concurrent calls from a single SubscribeFunc are
// not possible. For slow handlers, spawn a goroutine inside fn.
func SubscribeFunc(bus eventBus, eventType sdk.EventType, fn func(Event)) <-chan Event {
	ch := bus.Subscribe(eventType)
	go func() {
		for event := range ch {
			fn(event)
		}
	}()
	return ch
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
