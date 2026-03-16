package test_test

import (
	"net/http"
	"testing"

	"github.com/travisbale/mirage/sdk"
	"github.com/travisbale/mirage/test"
)

// TestAPI_DeleteSession verifies that a session can be deleted via the API
// and no longer appears in subsequent list responses.
func TestAPI_DeleteSession(t *testing.T) {
	harness := test.NewHarness(t)

	harness.UpstreamMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	test.DrainAndClose(harness.VictimGet(t, "/"))

	sessions, err := harness.API.ListSessions(sdk.SessionFilter{})
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if sessions.Total != 1 {
		t.Fatalf("expected 1 session before delete, got %d", sessions.Total)
	}

	if err := harness.API.DeleteSession(sessions.Items[0].ID); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}

	sessions, err = harness.API.ListSessions(sdk.SessionFilter{})
	if err != nil {
		t.Fatalf("ListSessions after delete: %v", err)
	}
	if sessions.Total != 0 {
		t.Errorf("expected 0 sessions after delete, got %d", sessions.Total)
	}
}

// TestAPI_ListSessions verifies that a session captured via the proxy appears
// in the sessions list returned by the API.
func TestAPI_ListSessions(t *testing.T) {
	harness := test.NewHarness(t)

	harness.UpstreamMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	test.DrainAndClose(harness.VictimGet(t, "/"))

	sessions, err := harness.API.ListSessions(sdk.SessionFilter{})
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if sessions.Total != 1 {
		t.Errorf("expected 1 session, got %d", sessions.Total)
	}
	if sessions.Items[0].Phishlet != "testsite" {
		t.Errorf("expected phishlet %q, got %q", "testsite", sessions.Items[0].Phishlet)
	}
}
