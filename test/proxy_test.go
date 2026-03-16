package test_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/travisbale/mirage/test"
	"github.com/travisbale/mirage/sdk"
)

// TestProxy_UnknownHostnameSpoofed verifies that requests to a hostname not
// registered by any phishlet receive a spoof response and create no session.
func TestProxy_UnknownHostnameSpoofed(t *testing.T) {
	harness := test.NewHarness(t)

	req, _ := http.NewRequest(http.MethodGet, "https://unknown.phish.test/", nil)
	resp, err := harness.Victim.Do(req)
	if err != nil {
		t.Fatalf("GET unknown hostname: %v", err)
	}
	test.DrainAndClose(resp)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 spoof, got %d", resp.StatusCode)
	}

	sessions, err := harness.API.ListSessions(sdk.SessionFilter{})
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if sessions.Total != 0 {
		t.Errorf("expected 0 sessions for unknown hostname, got %d", sessions.Total)
	}
}

// TestProxy_KnownHostnameProxied verifies that a request to the phishing hostname
// is forwarded upstream and the victim receives the upstream response.
func TestProxy_KnownHostnameProxied(t *testing.T) {
	harness := test.NewHarness(t)

	harness.UpstreamMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "hello from upstream")
	})

	resp := harness.VictimGet(t, "/")
	defer test.DrainAndClose(resp)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

// TestProxy_SessionCookieInjected verifies that the first response to the
// phishing hostname carries the session tracking cookie.
func TestProxy_SessionCookieInjected(t *testing.T) {
	harness := test.NewHarness(t)

	harness.UpstreamMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	resp := harness.VictimGet(t, "/")
	defer test.DrainAndClose(resp)

	found := false
	for _, c := range resp.Cookies() {
		if c.Name == "__ss" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected session tracking cookie (__ss) in response; got cookies: %v", resp.Cookies())
	}
}

// TestProxy_SubsequentRequestsReuseSession verifies that two requests from the
// same victim (cookie jar) map to a single session, not two.
func TestProxy_SubsequentRequestsReuseSession(t *testing.T) {
	harness := test.NewHarness(t)

	harness.UpstreamMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	test.DrainAndClose(harness.VictimGet(t, "/"))
	test.DrainAndClose(harness.VictimGet(t, "/page2"))

	sessions, err := harness.API.ListSessions(sdk.SessionFilter{})
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if sessions.Total != 1 {
		t.Errorf("expected 1 session for repeated requests, got %d", sessions.Total)
	}
}
