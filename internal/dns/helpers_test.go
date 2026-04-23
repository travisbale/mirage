package dns_test

import (
	"context"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/config"
	"github.com/travisbale/mirage/sdk"
)

// nopBus satisfies aitm.DNSService's eventBus dependency for tests that
// don't care about events. Subscribe returns a pre-closed channel.
type nopBus struct{}

func (nopBus) Publish(aitm.Event) {}
func (nopBus) Subscribe(sdk.EventType) (<-chan aitm.Event, func()) {
	ch := make(chan aitm.Event)
	close(ch)
	return ch, func() {}
}

type mockProvider struct {
	name        string
	createCalls int
	deleteCalls int
}

func (m *mockProvider) CreateRecord(_ context.Context, zone, name, typ, value string, ttl int) error {
	m.createCalls++
	return nil
}
func (m *mockProvider) UpdateRecord(_ context.Context, zone, name, typ, value string, ttl int) error {
	return nil
}
func (m *mockProvider) DeleteRecord(_ context.Context, zone, name, typ string) error {
	m.deleteCalls++
	return nil
}
func (m *mockProvider) Present(_ context.Context, domain, token, keyAuth string) error { return nil }
func (m *mockProvider) CleanUp(_ context.Context, domain, token, keyAuth string) error { return nil }
func (m *mockProvider) Ping(_ context.Context) error                                   { return nil }
func (m *mockProvider) Name() string                                                   { return m.name }

// providerConfig builds a minimal DNSProviderConfig for factory tests.
func providerConfig(provider string) config.DNSProviderConfig {
	return config.DNSProviderConfig{Provider: provider}
}
