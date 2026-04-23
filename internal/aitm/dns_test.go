package aitm_test

import (
	"context"
	"testing"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/sdk"
)

// fakeDNSProvider records all DNS operations for assertion.
type fakeDNSProvider struct {
	created []dnsRecord
	updated []dnsRecord
	deleted []dnsRecord
	// If set, CreateRecord returns this error.
	createErr error
}

type dnsRecord struct {
	Zone, Name, Type, Value string
	TTL                     int
}

func (f *fakeDNSProvider) CreateRecord(_ context.Context, zone, name, typ, value string, ttl int) error {
	if f.createErr != nil {
		return f.createErr
	}
	f.created = append(f.created, dnsRecord{zone, name, typ, value, ttl})
	return nil
}

func (f *fakeDNSProvider) UpdateRecord(_ context.Context, zone, name, typ, value string, ttl int) error {
	f.updated = append(f.updated, dnsRecord{zone, name, typ, value, ttl})
	return nil
}

func (f *fakeDNSProvider) DeleteRecord(_ context.Context, zone, name, typ string) error {
	f.deleted = append(f.deleted, dnsRecord{Zone: zone, Name: name, Type: typ})
	return nil
}

func (f *fakeDNSProvider) Present(context.Context, string, string, string) error { return nil }
func (f *fakeDNSProvider) CleanUp(context.Context, string, string, string) error { return nil }
func (f *fakeDNSProvider) Ping(context.Context) error                            { return nil }
func (f *fakeDNSProvider) Name() string                                          { return "fake" }

func TestDNSService_ListZones(t *testing.T) {
	zones := map[string]aitm.ZoneConfig{
		"example.com": {Zone: "example.com", ProviderName: "cf", ExternalIP: "1.2.3.4"},
		"evil.net":    {Zone: "evil.net", ProviderName: "r53", ExternalIP: "5.6.7.8"},
	}

	svc := aitm.NewDNSService(nil, zones, &stubBus{}, discardLogger())
	got := svc.ListZones()

	if len(got) != 2 {
		t.Fatalf("expected 2 zones, got %d", len(got))
	}

	found := map[string]bool{}
	for _, z := range got {
		found[z.Zone] = true
	}
	if !found["example.com"] || !found["evil.net"] {
		t.Errorf("expected both zones, got %v", got)
	}
}

func TestDNSService_ListZones_Empty(t *testing.T) {
	svc := aitm.NewDNSService(nil, nil, &stubBus{}, discardLogger())
	got := svc.ListZones()
	if len(got) != 0 {
		t.Fatalf("expected 0 zones, got %d", len(got))
	}
}

func TestDNSService_Reconcile(t *testing.T) {
	provider := &fakeDNSProvider{}
	providers := map[string]aitm.DNSProvider{"cf": provider}
	zones := map[string]aitm.ZoneConfig{
		"example.com": {Zone: "example.com", ProviderName: "cf", ExternalIP: "1.2.3.4"},
	}

	svc := aitm.NewDNSService(providers, zones, &stubBus{}, discardLogger())
	err := svc.Reconcile(context.Background(), []aitm.PhishletRecord{
		{Zone: "example.com", Name: "login.example.com"},
		{Zone: "example.com", Name: "api.example.com", IP: "9.9.9.9"},
	})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	if len(provider.created) != 2 {
		t.Fatalf("expected 2 records created, got %d", len(provider.created))
	}

	// First record should use the zone's external IP.
	if provider.created[0].Value != "1.2.3.4" {
		t.Errorf("expected zone IP 1.2.3.4, got %s", provider.created[0].Value)
	}
	// Second record overrides with its own IP.
	if provider.created[1].Value != "9.9.9.9" {
		t.Errorf("expected override IP 9.9.9.9, got %s", provider.created[1].Value)
	}
}

func TestDNSService_Reconcile_PublishesPerRecordPayload(t *testing.T) {
	t.Run("create path emits action=create", func(t *testing.T) {
		provider := &fakeDNSProvider{}
		bus := &stubBus{}
		svc := aitm.NewDNSService(
			map[string]aitm.DNSProvider{"cf": provider},
			map[string]aitm.ZoneConfig{
				"example.com": {Zone: "example.com", ProviderName: "cf", ExternalIP: "1.2.3.4"},
			},
			bus,
			discardLogger(),
		)

		if err := svc.Reconcile(context.Background(), []aitm.PhishletRecord{
			{Zone: "example.com", Name: "login.example.com"},
			{Zone: "example.com", Name: "api.example.com", IP: "9.9.9.9"},
		}); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}

		want := []aitm.DNSSyncPayload{
			{Zone: "example.com", Name: "login.example.com", Type: "A", Value: "1.2.3.4", Action: aitm.DNSActionCreate, Provider: "fake"},
			{Zone: "example.com", Name: "api.example.com", Type: "A", Value: "9.9.9.9", Action: aitm.DNSActionCreate, Provider: "fake"},
		}
		assertSyncPayloads(t, bus.published, want)
	})

	t.Run("update path emits action=update", func(t *testing.T) {
		provider := &fakeDNSProvider{createErr: aitm.ErrRecordExists}
		bus := &stubBus{}
		svc := aitm.NewDNSService(
			map[string]aitm.DNSProvider{"cf": provider},
			map[string]aitm.ZoneConfig{
				"example.com": {Zone: "example.com", ProviderName: "cf", ExternalIP: "1.2.3.4"},
			},
			bus,
			discardLogger(),
		)

		if err := svc.Reconcile(context.Background(), []aitm.PhishletRecord{
			{Zone: "example.com", Name: "login.example.com"},
		}); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}

		want := []aitm.DNSSyncPayload{
			{Zone: "example.com", Name: "login.example.com", Type: "A", Value: "1.2.3.4", Action: aitm.DNSActionUpdate, Provider: "fake"},
		}
		assertSyncPayloads(t, bus.published, want)
	})
}

func assertSyncPayloads(t *testing.T, events []aitm.Event, want []aitm.DNSSyncPayload) {
	t.Helper()
	if len(events) != len(want) {
		t.Fatalf("event count: got %d, want %d (events=%+v)", len(events), len(want), events)
	}
	for i, e := range events {
		if e.Type != sdk.EventDNSRecordSynced {
			t.Errorf("event %d type: got %q, want %q", i, e.Type, sdk.EventDNSRecordSynced)
		}
		got, ok := e.Payload.(aitm.DNSSyncPayload)
		if !ok {
			t.Fatalf("event %d payload type: got %T, want aitm.DNSSyncPayload", i, e.Payload)
		}
		if got != want[i] {
			t.Errorf("event %d payload:\n  got:  %+v\n  want: %+v", i, got, want[i])
		}
	}
}

func TestDNSService_Reconcile_FallsBackToUpdate(t *testing.T) {
	provider := &fakeDNSProvider{createErr: aitm.ErrRecordExists}
	providers := map[string]aitm.DNSProvider{"cf": provider}
	zones := map[string]aitm.ZoneConfig{
		"example.com": {Zone: "example.com", ProviderName: "cf", ExternalIP: "1.2.3.4"},
	}

	svc := aitm.NewDNSService(providers, zones, &stubBus{}, discardLogger())
	err := svc.Reconcile(context.Background(), []aitm.PhishletRecord{
		{Zone: "example.com", Name: "login.example.com"},
	})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	if len(provider.updated) != 1 {
		t.Fatalf("expected 1 update (fallback from create), got %d", len(provider.updated))
	}
	if provider.updated[0].Name != "login.example.com" {
		t.Errorf("expected login.example.com, got %s", provider.updated[0].Name)
	}
}

func TestDNSService_RemoveRecords(t *testing.T) {
	provider := &fakeDNSProvider{}
	providers := map[string]aitm.DNSProvider{"cf": provider}
	zones := map[string]aitm.ZoneConfig{
		"example.com": {Zone: "example.com", ProviderName: "cf", ExternalIP: "1.2.3.4"},
	}

	svc := aitm.NewDNSService(providers, zones, &stubBus{}, discardLogger())
	err := svc.RemoveRecords(context.Background(), []aitm.PhishletRecord{
		{Zone: "example.com", Name: "login.example.com"},
	})
	if err != nil {
		t.Fatalf("RemoveRecords: %v", err)
	}

	if len(provider.deleted) != 1 {
		t.Fatalf("expected 1 record deleted, got %d", len(provider.deleted))
	}
	if provider.deleted[0].Name != "login.example.com" {
		t.Errorf("expected login.example.com, got %s", provider.deleted[0].Name)
	}
}
