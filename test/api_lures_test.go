package test_test

import (
	"net/http"
	"testing"

	"github.com/travisbale/mirage/sdk"
	"github.com/travisbale/mirage/test"
)

// TestAPI_CreateAndDeleteLure verifies that a lure can be created, appears in
// the list, and disappears after deletion.
func TestAPI_CreateAndDeleteLure(t *testing.T) {
	harness := test.NewHarness(t)

	lure, err := harness.API.CreateLure(sdk.CreateLureRequest{
		Phishlet:    "testsite",
		Path:        "/go/test",
		RedirectURL: "https://testsite.internal/",
	})
	if err != nil {
		t.Fatalf("CreateLure: %v", err)
	}

	lures, err := harness.API.ListLures()
	if err != nil {
		t.Fatalf("ListLures: %v", err)
	}
	found := false
	for _, l := range lures.Items {
		if l.ID == lure.ID {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("created lure %q not found in list", lure.ID)
	}

	if err := harness.API.DeleteLure(lure.ID); err != nil {
		t.Fatalf("DeleteLure: %v", err)
	}

	lures, err = harness.API.ListLures()
	if err != nil {
		t.Fatalf("ListLures after delete: %v", err)
	}
	for _, l := range lures.Items {
		if l.ID == lure.ID {
			t.Errorf("deleted lure %q still appears in list", lure.ID)
		}
	}
}

// TestAPI_PausedLureSpoofs verifies that a paused lure causes the proxy to
// return a spoof response, and that unpausing restores normal proxying.
func TestAPI_PausedLureSpoofs(t *testing.T) {
	harness := test.NewHarness(t)

	harness.UpstreamMux.HandleFunc("/go/test", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	lure, err := harness.API.CreateLure(sdk.CreateLureRequest{
		Phishlet:    "testsite",
		Path:        "/go/test",
		RedirectURL: "https://testsite.internal/",
	})
	if err != nil {
		t.Fatalf("CreateLure: %v", err)
	}

	if err := harness.API.PauseLure(lure.ID, sdk.PauseLureRequest{Duration: "1h"}); err != nil {
		t.Fatalf("PauseLure: %v", err)
	}

	// Paused lure: request to the lure path should be spoofed (no session cookie).
	resp := harness.VictimGet(t, "/go/test")
	test.DrainAndClose(resp)
	for _, c := range resp.Cookies() {
		if c.Name == "__ss" {
			t.Error("expected no session tracking cookie for paused lure")
		}
	}

	// Unpause: same path should now be proxied (session cookie injected).
	if err := harness.API.UnpauseLure(lure.ID); err != nil {
		t.Fatalf("UnpauseLure: %v", err)
	}

	resp = harness.VictimGet(t, "/go/test")
	test.DrainAndClose(resp)
	found := false
	for _, c := range resp.Cookies() {
		if c.Name == "__ss" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected session tracking cookie after unpausing lure")
	}
}
