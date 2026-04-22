package notify

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/sdk"
)

const (
	maxRetries   = 3
	baseBackoff  = 1 * time.Second
	maxBackoff   = 4 * time.Second
	jitterFactor = 0.5
)

// eventBus is the subset of the event bus interface needed by the dispatcher.
type eventBus interface {
	Publish(event aitm.Event)
	Subscribe(eventType sdk.EventType) <-chan aitm.Event
	Unsubscribe(eventType sdk.EventType, ch <-chan aitm.Event)
}

// channelBinding pairs a Channel implementation with its event filter.
type channelBinding struct {
	channel Channel
	config  *aitm.NotificationChannel
}

// Dispatcher subscribes to events on the bus, builds Notification payloads,
// and fans out to registered channels with retries.
type Dispatcher struct {
	bus    eventBus
	logger *slog.Logger

	mu       sync.Mutex
	bindings []channelBinding
	unsubs   []func()
	wg       sync.WaitGroup
	ctx      context.Context
	cancel   context.CancelFunc
}

func NewDispatcher(bus eventBus, logger *slog.Logger) *Dispatcher {
	return &Dispatcher{
		bus:    bus,
		logger: logger,
	}
}

// Start subscribes to events for all configured channels and begins dispatching.
func (d *Dispatcher) Start(ctx context.Context, channels []*aitm.NotificationChannel) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.ctx, d.cancel = context.WithCancel(ctx)
	d.subscribe(channels)
}

// Reload replaces the active channel set. Called when channels are added or
// removed via the API.
func (d *Dispatcher) Reload(channels []*aitm.NotificationChannel) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.unsubscribe()
	d.subscribe(channels)
}

// Shutdown stops the dispatcher and waits for in-flight deliveries to complete
// or the context deadline to expire.
func (d *Dispatcher) Shutdown(ctx context.Context) error {
	d.mu.Lock()
	if d.cancel != nil {
		d.cancel()
	}
	d.unsubscribe()
	d.mu.Unlock()

	done := make(chan struct{})
	go func() {
		d.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// subscribe builds channel bindings and subscribes to the union of event types.
// Caller must hold d.mu.
func (d *Dispatcher) subscribe(channels []*aitm.NotificationChannel) {
	d.bindings = make([]channelBinding, 0, len(channels))
	for _, ch := range channels {
		if !ch.Enabled {
			continue
		}
		channel := buildChannel(ch)
		if channel == nil {
			d.logger.Warn("unknown channel type, skipping", "type", ch.Type, "id", ch.ID)
			continue
		}
		d.bindings = append(d.bindings, channelBinding{channel: channel, config: ch})
	}

	if len(d.bindings) == 0 {
		return
	}

	// Compute the union of event types across all channel filters.
	eventTypes := d.requiredEventTypes()
	d.unsubs = make([]func(), 0, len(eventTypes))
	for _, eventType := range eventTypes {
		unsub := aitm.SubscribeFunc(d.bus, eventType, func(event aitm.Event) {
			d.dispatch(event)
		})
		d.unsubs = append(d.unsubs, unsub)
	}
}

// unsubscribe removes all event bus subscriptions. Caller must hold d.mu.
func (d *Dispatcher) unsubscribe() {
	for _, unsub := range d.unsubs {
		unsub()
	}
	d.unsubs = nil
	d.bindings = nil
}

// requiredEventTypes returns the deduplicated union of event types needed
// across all active channel bindings. Caller must hold d.mu.
func (d *Dispatcher) requiredEventTypes() []sdk.EventType {
	seen := make(map[sdk.EventType]bool)
	for _, binding := range d.bindings {
		if len(binding.config.Filter) == 0 {
			// No filter = all events. Return the full set.
			return sdk.AllEventTypes()
		}
		for _, eventType := range binding.config.Filter {
			seen[eventType] = true
		}
	}
	types := make([]sdk.EventType, 0, len(seen))
	for eventType := range seen {
		types = append(types, eventType)
	}
	return types
}

// dispatch builds a notification and delivers it to all matching channels.
func (d *Dispatcher) dispatch(event aitm.Event) {
	d.mu.Lock()
	bindings := make([]channelBinding, len(d.bindings))
	copy(bindings, d.bindings)
	ctx := d.ctx
	d.mu.Unlock()

	// Filter first to avoid building the notification payload when no channels match.
	var matched []Channel
	for _, binding := range bindings {
		if binding.config.Accepts(event.Type) {
			matched = append(matched, binding.channel)
		}
	}
	if len(matched) == 0 {
		return
	}

	notification := buildNotification(event)
	for _, ch := range matched {
		d.wg.Add(1)
		go func(ch Channel) {
			defer d.wg.Done()
			d.deliverWithRetry(ctx, ch, notification)
		}(ch)
	}
}

// deliverWithRetry attempts to send a notification with exponential backoff.
func (d *Dispatcher) deliverWithRetry(ctx context.Context, channel Channel, notification Notification) {
	for attempt := range maxRetries {
		err := channel.Send(ctx, notification)
		if err == nil {
			return
		}

		if !isRetryable(err) {
			d.logger.Error("notification delivery failed (permanent)",
				"channel", channel.Name(),
				"event", string(notification.Event),
				"error", err,
			)
			return
		}

		if attempt == maxRetries-1 {
			d.logger.Error("notification delivery failed (retries exhausted)",
				"channel", channel.Name(),
				"event", string(notification.Event),
				"attempts", maxRetries,
				"error", err,
			)
			return
		}

		d.logger.Warn("notification delivery failed, retrying",
			"channel", channel.Name(),
			"event", string(notification.Event),
			"attempt", attempt+1,
			"error", err,
		)

		timer := time.NewTimer(backoffDuration(attempt))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// Test sends a test notification through a single channel configuration.
func (d *Dispatcher) Test(ctx context.Context, config *aitm.NotificationChannel) error {
	channel := buildChannel(config)
	if channel == nil {
		return fmt.Errorf("unknown channel type: %s", config.Type)
	}

	notification := Notification{
		Event:     sdk.EventSessionCompleted,
		Timestamp: time.Now(),
		Session: &SessionData{
			ID:         "test-session-id",
			Phishlet:   "test-phishlet",
			RemoteAddr: "203.0.113.42",
			UserAgent:  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Test Browser",
			Username:   "testuser@example.com",
			StartedAt:  time.Now().Add(-5 * time.Minute),
		},
	}

	return channel.Send(ctx, notification)
}

// buildChannel constructs the appropriate Channel implementation for a config entry.
func buildChannel(config *aitm.NotificationChannel) Channel {
	switch config.Type {
	case sdk.ChannelWebhook:
		return NewWebhookChannel(config.URL, config.AuthHeader)
	case sdk.ChannelSlack:
		return NewSlackChannel(config.URL)
	default:
		return nil
	}
}

func backoffDuration(attempt int) time.Duration {
	backoff := min(baseBackoff*(1<<attempt), maxBackoff)
	jitter := time.Duration(float64(backoff) * jitterFactor * rand.Float64())
	return backoff + jitter
}

// httpError represents a non-2xx response from a notification endpoint.
type httpError struct {
	StatusCode int
}

func (e *httpError) Error() string {
	return fmt.Sprintf("HTTP %d", e.StatusCode)
}

// isRetryable returns true for network errors and 5xx HTTP responses.
// 4xx errors are considered permanent (bad config).
func isRetryable(err error) bool {
	if httpErr, ok := errors.AsType[*httpError](err); ok {
		return httpErr.StatusCode >= 500
	}
	// Network errors, timeouts, etc. are retryable.
	return true
}
