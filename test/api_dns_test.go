package test_test

import (
	"testing"

	"github.com/travisbale/mirage/test"
)

// TestAPI_ListDNSProviders verifies that the DNS providers endpoint returns
// successfully. The test harness has no providers configured, so the list
// should be empty.
func TestAPI_ListDNSProviders(t *testing.T) {
	t.Parallel()
	harness := test.NewHarness(t)

	providers, err := harness.API.ListDNSProviders()
	if err != nil {
		t.Fatalf("ListDNSProviders: %v", err)
	}
	if len(providers) != 0 {
		t.Errorf("expected 0 providers, got %d", len(providers))
	}
}

// TestAPI_ListDNSZones verifies that the DNS zones endpoint returns
// successfully. No zones exist because the test harness has no DNS
// providers configured.
func TestAPI_ListDNSZones(t *testing.T) {
	t.Parallel()
	harness := test.NewHarness(t)

	zones, err := harness.API.ListDNSZones()
	if err != nil {
		t.Fatalf("ListDNSZones: %v", err)
	}
	if len(zones) != 0 {
		t.Errorf("expected 0 zones, got %d", len(zones))
	}
}

// TestAPI_SyncDNS verifies that the DNS sync endpoint succeeds. With no
// DNS providers configured the reconciliation is a no-op.
func TestAPI_SyncDNS(t *testing.T) {
	t.Parallel()
	harness := test.NewHarness(t)

	if err := harness.API.SyncDNS(); err != nil {
		t.Fatalf("SyncDNS: %v", err)
	}
}
