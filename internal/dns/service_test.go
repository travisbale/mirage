package dns_test

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/events"
	"github.com/travisbale/mirage/sdk"
)

func TestDNSService_ReconcileRoutesToCorrectProvider(t *testing.T) {
	p1 := &mockProvider{name: "cloudflare"}
	p2 := &mockProvider{name: "builtin"}

	svc := aitm.NewDNSService(
		map[string]aitm.DNSProvider{"cf": p1, "bi": p2},
		map[string]aitm.ZoneConfig{
			"attacker.com": {Zone: "attacker.com", ProviderName: "cf", ExternalIP: "1.2.3.4"},
			"evil.net":     {Zone: "evil.net", ProviderName: "bi", ExternalIP: "5.6.7.8"},
		},
		nopBus{},
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)

	err := svc.Reconcile(context.Background(), []aitm.PhishletRecord{
		{Zone: "attacker.com", Name: "mail"},
		{Zone: "evil.net", Name: "www"},
	})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if p1.createCalls != 1 {
		t.Errorf("p1 createCalls: got %d, want 1", p1.createCalls)
	}
	if p2.createCalls != 1 {
		t.Errorf("p2 createCalls: got %d, want 1", p2.createCalls)
	}
}

func TestDNSService_Reconcile_EmitsEvent(t *testing.T) {
	bus := events.NewBus(8)
	syncedEvents, unsubscribe := bus.Subscribe(sdk.EventDNSRecordSynced)
	defer unsubscribe()

	svc := aitm.NewDNSService(
		map[string]aitm.DNSProvider{"bi": &mockProvider{name: "builtin"}},
		map[string]aitm.ZoneConfig{
			"attacker.com": {Zone: "attacker.com", ProviderName: "bi", ExternalIP: "1.2.3.4"},
		},
		bus,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)

	if err := svc.Reconcile(context.Background(), []aitm.PhishletRecord{
		{Zone: "attacker.com", Name: "login"},
	}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	select {
	case e := <-syncedEvents:
		if e.Type != sdk.EventDNSRecordSynced {
			t.Errorf("event type: got %q, want %q", e.Type, sdk.EventDNSRecordSynced)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timed out waiting for EventDNSRecordSynced")
	}
}

func TestDNSService_RemoveRecords(t *testing.T) {
	p := &mockProvider{name: "builtin"}
	svc := aitm.NewDNSService(
		map[string]aitm.DNSProvider{"bi": p},
		map[string]aitm.ZoneConfig{
			"attacker.com": {Zone: "attacker.com", ProviderName: "bi", ExternalIP: "1.2.3.4"},
		},
		nopBus{},
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)

	if err := svc.RemoveRecords(context.Background(), []aitm.PhishletRecord{
		{Zone: "attacker.com", Name: "login"},
	}); err != nil {
		t.Fatalf("RemoveRecords: %v", err)
	}
	if p.deleteCalls != 1 {
		t.Errorf("deleteCalls: got %d, want 1", p.deleteCalls)
	}
}
