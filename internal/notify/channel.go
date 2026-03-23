package notify

import "context"

// Channel delivers a notification to an external system.
// Implementations must be safe for concurrent use from multiple goroutines.
type Channel interface {
	// Send delivers a single notification. The context carries the shutdown
	// deadline — implementations should respect cancellation.
	Send(ctx context.Context, notification Notification) error

	// Name returns a human-readable identifier for logging (e.g., "webhook", "slack").
	Name() string
}
