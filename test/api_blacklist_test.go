package test_test

import (
	"net/http"
	"testing"

	"github.com/travisbale/mirage/sdk"
	"github.com/travisbale/mirage/test"
)

// TestAPI_BlacklistCRUD verifies that blacklist entries can be added, listed,
// and removed via the API.
func TestAPI_BlacklistCRUD(t *testing.T) {
	harness := test.NewHarness(t)

	if _, err := harness.API.AddBlacklistEntry(sdk.AddBlacklistEntryRequest{Value: "10.0.0.1"}); err != nil {
		t.Fatalf("AddBlacklistEntry: %v", err)
	}

	list, err := harness.API.ListBlacklist()
	if err != nil {
		t.Fatalf("ListBlacklist: %v", err)
	}
	found := false
	for _, entry := range list.Items {
		if entry.Value == "10.0.0.1" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 10.0.0.1 in blacklist after adding")
	}

	if err := harness.API.RemoveBlacklistEntry("10.0.0.1"); err != nil {
		t.Fatalf("RemoveBlacklistEntry: %v", err)
	}

	list, err = harness.API.ListBlacklist()
	if err != nil {
		t.Fatalf("ListBlacklist after remove: %v", err)
	}
	for _, entry := range list.Items {
		if entry.Value == "10.0.0.1" {
			t.Error("expected 10.0.0.1 to be removed from blacklist")
		}
	}
}

// TestAPI_BlacklistBlocksVictim verifies that a blacklisted IP receives a spoof
// response with no session tracking cookie, proving no session was created.
// Note: blacklisting 127.0.0.1 also blocks the API client (also on loopback),
// so we assert via the response rather than via a follow-up API call.
func TestAPI_BlacklistBlocksVictim(t *testing.T) {
	harness := test.NewHarness(t)

	// The victim dials from 127.0.0.1.
	if _, err := harness.API.AddBlacklistEntry(sdk.AddBlacklistEntryRequest{Value: "127.0.0.1"}); err != nil {
		t.Fatalf("AddBlacklistEntry: %v", err)
	}

	resp := harness.VictimGet(t, "/")
	test.DrainAndClose(resp)

	// Blacklisted requests are spoofed — the proxy returns the default page with no session cookie.
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 spoof response, got %d", resp.StatusCode)
	}
	for _, c := range resp.Cookies() {
		if c.Name == "__ss" {
			t.Error("expected no session tracking cookie for blacklisted IP")
		}
	}
}
