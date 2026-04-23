// Package events provides an in-process publish/subscribe event bus that
// implements the eventBus interface defined in the aitm package.
package events

import (
	"log/slog"
	"sync"
	"time"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/sdk"
)

// DefaultBufferSize is the channel buffer size used when none is specified.
const DefaultBufferSize = 64

// Bus is a goroutine-safe publish/subscribe bus backed by in-process
// Go channels.
//
// Delivery guarantee: best-effort, in-process only. Events are never persisted.
// If a subscriber's channel is full when Publish is called, the event is dropped
// for that subscriber and a warning is logged. The publisher is never blocked.
type Bus struct {
	bufSize int
	mu      sync.RWMutex
	subs    map[sdk.EventType][]*subEntry
}

type subEntry struct {
	ch chan aitm.Event
}

func NewBus(bufSize int) *Bus {
	if bufSize <= 0 {
		bufSize = DefaultBufferSize
	}
	return &Bus{
		bufSize: bufSize,
		subs:    make(map[sdk.EventType][]*subEntry),
	}
}

// Publish sends e to all subscribers registered for e.Type.
// e.OccurredAt is set to time.Now() before delivery regardless of what the
// caller provides. If a subscriber's channel is full the event is dropped for
// that subscriber and a warning is written to the default slog logger.
//
// The read lock is held across the send loop to prevent Unsubscribe from
// closing a subscriber's channel between iteration and send (which would
// panic). Sends are non-blocking (select + default), so the critical section
// stays short: concurrent publishers still run in parallel, and an
// Unsubscribe call only waits for in-flight publishes to return.
func (b *Bus) Publish(event aitm.Event) {
	event.OccurredAt = time.Now()

	b.mu.RLock()
	defer b.mu.RUnlock()

	for _, entry := range b.subs[event.Type] {
		select {
		case entry.ch <- event:
		default:
			slog.Warn("events: subscriber channel full, dropping event",
				"type", string(event.Type),
			)
		}
	}
}

// Subscribe registers a subscriber for eventType and returns a buffered
// channel of events plus an unsubscribe function. The unsubscribe func is
// safe to call multiple times.
func (b *Bus) Subscribe(eventType sdk.EventType) (events <-chan aitm.Event, unsubscribe func()) {
	ch := make(chan aitm.Event, b.bufSize)
	entry := &subEntry{ch: ch}

	b.mu.Lock()
	b.subs[eventType] = append(b.subs[eventType], entry)
	b.mu.Unlock()

	return ch, func() { b.unsubscribe(eventType, entry) }
}

// unsubscribe removes entry from the subscriber list for eventType and
// closes its channel. Idempotent: after the first call the entry is no
// longer in the slice and subsequent calls are no-ops, so the unsubscribe
// closure returned from Subscribe is safe to invoke multiple times.
func (b *Bus) unsubscribe(eventType sdk.EventType, entry *subEntry) {
	b.mu.Lock()
	defer b.mu.Unlock()

	entries := b.subs[eventType]
	for i, e := range entries {
		if e != entry {
			continue
		}
		close(e.ch)
		b.subs[eventType] = swapDelete(entries, i)
		if len(b.subs[eventType]) == 0 {
			delete(b.subs, eventType)
		}

		return
	}
}

// swapDelete removes s[i] in O(1) by moving the last element into its slot
// and truncating. Used when element order is irrelevant.
func swapDelete[T any](s []T, i int) []T {
	last := len(s) - 1
	s[i] = s[last]
	return s[:last]
}
