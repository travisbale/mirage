// Package events provides an in-process publish/subscribe event bus that
// implements the eventBus interface defined in the aitm package.
package events

import (
	"log/slog"
	"sync"
	"time"

	"github.com/travisbale/mirage/internal/aitm"
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
	subs    map[aitm.EventType][]subEntry
}

// subEntry pairs a bidirectional channel with a closed flag so that
// Unsubscribe is idempotent and double-close is prevented.
type subEntry struct {
	ch     chan aitm.Event
	closed bool
}

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
func (b *Bus) Publish(event aitm.Event) {
	event.OccurredAt = time.Now()

	b.mu.RLock()
	entries := b.subs[event.Type]
	// Copy the slice under the read lock to avoid holding it during sends,
	// which can block briefly when waking a receiver goroutine.
	snapshot := make([]subEntry, len(entries))
	copy(snapshot, entries)
	b.mu.RUnlock()

	for _, entry := range snapshot {
		select {
		case entry.ch <- event:
		default:
			slog.Warn("events: subscriber channel full, dropping event",
				"type", string(event.Type),
			)
		}
	}
}

// Subscribe returns a buffered channel for the given event type.
func (b *Bus) Subscribe(eventType aitm.EventType) <-chan aitm.Event {
	ch := make(chan aitm.Event, b.bufSize)
	b.mu.Lock()
	b.subs[eventType] = append(b.subs[eventType], subEntry{ch: ch})
	b.mu.Unlock()
	return ch
}

// Unsubscribe removes ch from the subscriber list for t and closes it.
// Safe to call multiple times for the same channel — subsequent calls are no-ops.
func (b *Bus) Unsubscribe(eventType aitm.EventType, ch <-chan aitm.Event) {
	b.mu.Lock()
	defer b.mu.Unlock()

	entries := b.subs[eventType]
	for i, entry := range entries {
		// Compare by converting the bidirectional internal channel to
		// receive-only, matching the type of the ch parameter.
		if (<-chan aitm.Event)(entry.ch) == ch {
			if entry.closed {
				return // already unsubscribed — no-op
			}
			entries[i].closed = true
			close(entry.ch)

			last := len(entries) - 1
			entries[i] = entries[last]
			b.subs[eventType] = entries[:last]
			return
		}
	}
}
