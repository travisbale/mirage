package aitm

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/travisbale/mirage/sdk"
)

// NotificationChannel is a configured notification destination.
type NotificationChannel struct {
	ID         string
	Type       sdk.ChannelType
	URL        string
	AuthHeader string          // optional Authorization header (webhook only)
	Filter     []sdk.EventType // event type filter; empty = all events
	Enabled    bool
	CreatedAt  time.Time
}

// Accepts reports whether the channel should receive the given event type.
// An empty filter means all events are accepted.
func (ch *NotificationChannel) Accepts(eventType sdk.EventType) bool {
	return len(ch.Filter) == 0 || slices.Contains(ch.Filter, eventType)
}

// notificationStore persists notification channel configuration.
type notificationStore interface {
	CreateChannel(ch *NotificationChannel) error
	GetChannel(id string) (*NotificationChannel, error)
	DeleteChannel(id string) error
	ListChannels() ([]*NotificationChannel, error)
}

// notificationDispatcher delivers notifications to external systems.
type notificationDispatcher interface {
	Start(ctx context.Context, channels []*NotificationChannel)
	Shutdown(ctx context.Context) error
	Reload(channels []*NotificationChannel)
	Test(ctx context.Context, ch *NotificationChannel) error
}

// NotificationService owns notification channel lifecycle — CRUD, dispatcher
// reload, and test delivery. The API handler delegates to this service.
type NotificationService struct {
	Store      notificationStore
	Dispatcher notificationDispatcher
}

// Start loads channels from the store and starts the dispatcher.
func (s *NotificationService) Start(ctx context.Context) {
	channels, _ := s.Store.ListChannels()
	s.Dispatcher.Start(ctx, channels)
}

// Shutdown stops the dispatcher and waits for in-flight deliveries.
func (s *NotificationService) Shutdown(ctx context.Context) error {
	return s.Dispatcher.Shutdown(ctx)
}

func (s *NotificationService) Create(channel *NotificationChannel) error {
	for _, eventType := range channel.Filter {
		if !eventType.Valid() {
			return fmt.Errorf("unknown event type: %s", eventType)
		}
	}

	channel.ID = uuid.New().String()
	channel.Enabled = true
	channel.CreatedAt = time.Now()

	if err := s.Store.CreateChannel(channel); err != nil {
		return err
	}
	s.reload()
	return nil
}

func (m *NotificationService) Delete(id string) error {
	if err := m.Store.DeleteChannel(id); err != nil {
		return err
	}
	m.reload()
	return nil
}

func (m *NotificationService) Get(id string) (*NotificationChannel, error) {
	return m.Store.GetChannel(id)
}

func (m *NotificationService) List() ([]*NotificationChannel, error) {
	return m.Store.ListChannels()
}

func (m *NotificationService) Test(ctx context.Context, id string) error {
	channel, err := m.Store.GetChannel(id)
	if err != nil {
		return err
	}
	return m.Dispatcher.Test(ctx, channel)
}

func (m *NotificationService) reload() {
	channels, err := m.Store.ListChannels()
	if err != nil {
		return
	}
	m.Dispatcher.Reload(channels)
}
