// Package events provides an in-process publish/subscribe event bus that
// implements aitm.EventBus.
package events

import (
	"log/slog"
	"sync"
	"time"

	"github.com/travisbale/mirage/internal/aitm"
)

// DefaultBufferSize is the channel buffer size used when none is specified.
const DefaultBufferSize = 64

// Compile-time check: Bus satisfies aitm.EventBus.
var _ aitm.EventBus = (*Bus)(nil)

// Bus is a goroutine-safe publish/subscribe bus backed by in-process
// Go channels.
//
// Delivery guarantee: best-effort, in-process only. Events are never persisted.
// If a subscriber's channel is full when Publish is called, the event is dropped
// for that subscriber and a warning is logged. The publisher is never blocked.
type Bus struct {
	bufSize int
	mu      sync.RWMutex
	subs    map[aitm.EventType][]subEntry
}

// subEntry pairs a bidirectional channel with a closed flag so that
// Unsubscribe is idempotent and double-close is prevented.
type subEntry struct {
	ch     chan aitm.Event
	closed bool
}

// NewBus creates a new Bus with the given channel buffer size.
// Pass DefaultBufferSize (64) if you have no specific requirement.
func NewBus(bufSize int) *Bus {
	if bufSize <= 0 {
		bufSize = DefaultBufferSize
	}
	return &Bus{
		bufSize: bufSize,
		subs:    make(map[aitm.EventType][]subEntry),
	}
}

// Publish sends e to all subscribers registered for e.Type.
// e.OccurredAt is set to time.Now() before delivery regardless of what the
// caller provides. If a subscriber's channel is full the event is dropped for
// that subscriber and a warning is written to the default slog logger.
func (b *Bus) Publish(e aitm.Event) {
	e.OccurredAt = time.Now()

	b.mu.RLock()
	entries := b.subs[e.Type]
	// Copy the slice under the read lock to avoid holding it during sends,
	// which can block briefly when waking a receiver goroutine.
	snapshot := make([]subEntry, len(entries))
	copy(snapshot, entries)
	b.mu.RUnlock()

	for _, sub := range snapshot {
		select {
		case sub.ch <- e:
		default:
			slog.Warn("events: subscriber channel full, dropping event",
				"type", string(e.Type),
			)
		}
	}
}

// Subscribe creates and registers a new channel for events of type t.
// The returned channel is buffered with the size set at bus construction.
func (b *Bus) Subscribe(t aitm.EventType) <-chan aitm.Event {
	ch := make(chan aitm.Event, b.bufSize)
	b.mu.Lock()
	b.subs[t] = append(b.subs[t], subEntry{ch: ch})
	b.mu.Unlock()
	return ch
}

// SubscribeFunc subscribes to eventType on bus and starts a goroutine that
// calls fn for each received event. The goroutine exits when the subscription
// channel is closed (i.e., when Unsubscribe is called for the returned channel).
//
// fn is called sequentially — concurrent calls from a single SubscribeFunc are
// not possible. For slow handlers, spawn a goroutine inside fn.
func SubscribeFunc(bus aitm.EventBus, eventType aitm.EventType, fn func(aitm.Event)) <-chan aitm.Event {
	ch := bus.Subscribe(eventType)
	go func() {
		for e := range ch {
			fn(e)
		}
	}()
	return ch
}

// Unsubscribe removes ch from the subscriber list for t and closes it.
// Safe to call multiple times for the same channel — subsequent calls are no-ops.
func (b *Bus) Unsubscribe(t aitm.EventType, ch <-chan aitm.Event) {
	b.mu.Lock()
	defer b.mu.Unlock()

	entries := b.subs[t]
	for i, sub := range entries {
		// Compare by converting the bidirectional internal channel to
		// receive-only, matching the type of the ch parameter.
		if (<-chan aitm.Event)(sub.ch) == ch {
			if sub.closed {
				return // already unsubscribed — no-op
			}
			entries[i].closed = true
			close(sub.ch)

			// Fast delete: swap with last element, shrink slice.
			last := len(entries) - 1
			entries[i] = entries[last]
			b.subs[t] = entries[:last]
			return
		}
	}
	// ch not found — no-op.
}
