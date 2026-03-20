package test_test

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/travisbale/mirage/sdk"
	"github.com/travisbale/mirage/test"
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

// TestProxy_InterceptPreventsUpstreamCall verifies that an intercept rule
// returns a static response without forwarding the request to the upstream.
func TestProxy_InterceptPreventsUpstreamCall(t *testing.T) {
	harness := test.NewHarness(t)

	upstreamCalled := false
	harness.UpstreamMux.HandleFunc("/api/telemetry", func(w http.ResponseWriter, r *http.Request) {
		upstreamCalled = true
		w.WriteHeader(http.StatusOK)
	})

	resp := harness.VictimPostJSON(t, "/api/telemetry", `{"ua":"test"}`)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 from intercept, got %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), `"status":"ok"`) {
		t.Errorf("expected intercept body, got %q", string(body))
	}
	if upstreamCalled {
		t.Error("expected upstream NOT to be called for intercepted path")
	}
}

// TestProxy_AutoFilterRewritesDomains verifies that auto_filter rewrites
// upstream domain references in response bodies to the phishing domain.
func TestProxy_AutoFilterRewritesDomains(t *testing.T) {
	harness := test.NewHarness(t)

	harness.UpstreamMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<a href="https://login.testsite.internal/page">link</a>`)
	})

	resp := harness.VictimGet(t, "/")
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	// auto_filter should rewrite the upstream domain to the phishing domain.
	if !strings.Contains(string(body), "login.phish.test") {
		t.Errorf("expected auto_filter to rewrite domain, got: %s", string(body))
	}
	if strings.Contains(string(body), "testsite.internal") {
		t.Errorf("expected upstream domain to be rewritten, but found testsite.internal in: %s", string(body))
	}
}
