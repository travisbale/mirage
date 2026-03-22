package dns_test

import (
	"context"
	"testing"
	"time"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/events"
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
		&events.NoOpBus{},
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
	ch := bus.Subscribe(aitm.EventDNSRecordSynced)
	defer bus.Unsubscribe(aitm.EventDNSRecordSynced, ch)

	svc := aitm.NewDNSService(
		map[string]aitm.DNSProvider{"bi": &mockProvider{name: "builtin"}},
		map[string]aitm.ZoneConfig{
			"attacker.com": {Zone: "attacker.com", ProviderName: "bi", ExternalIP: "1.2.3.4"},
		},
		bus,
	)

	if err := svc.Reconcile(context.Background(), []aitm.PhishletRecord{
		{Zone: "attacker.com", Name: "login"},
	}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	select {
	case e := <-ch:
		if e.Type != aitm.EventDNSRecordSynced {
			t.Errorf("event type: got %q, want %q", e.Type, aitm.EventDNSRecordSynced)
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
		&events.NoOpBus{},
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
