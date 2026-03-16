package test_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/travisbale/mirage/sdk"
	"github.com/travisbale/mirage/test"
)

// TestSessions_CredentialExtraction verifies that a POST to the login path
// with form-encoded credentials results in the session recording them.
func TestSessions_CredentialExtraction(t *testing.T) {
	harness := test.NewHarness(t)

	harness.UpstreamMux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// First GET to establish a session and receive the tracking cookie.
	test.DrainAndClose(harness.VictimGet(t, "/login"))

	// POST credentials to the login path.
	resp := harness.VictimPost(t, "/login", "username=alice&password=s3cret")
	test.DrainAndClose(resp)

	sessions, err := harness.API.ListSessions(sdk.SessionFilter{})
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if sessions.Total != 1 {
		t.Fatalf("expected 1 session, got %d", sessions.Total)
	}
	sess := sessions.Items[0]
	if sess.Username != "alice" {
		t.Errorf("username: got %q, want %q", sess.Username, "alice")
	}
	if sess.Password != "s3cret" {
		t.Errorf("password: got %q, want %q", sess.Password, "s3cret")
	}
}

// TestSessions_NoCaptureOnNonLoginPath verifies that a POST to a non-login
// path does not populate credentials on the session.
func TestSessions_NoCaptureOnNonLoginPath(t *testing.T) {
	harness := test.NewHarness(t)

	harness.UpstreamMux.HandleFunc("/other", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	test.DrainAndClose(harness.VictimGet(t, "/other"))
	test.DrainAndClose(harness.VictimPost(t, "/other", "username=alice&password=s3cret"))

	sessions, err := harness.API.ListSessions(sdk.SessionFilter{})
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if sessions.Total != 1 {
		t.Fatalf("expected 1 session, got %d", sessions.Total)
	}
	sess := sessions.Items[0]
	if sess.Username != "" || sess.Password != "" {
		t.Errorf("expected no credentials on non-login path, got username=%q password=%q",
			sess.Username, sess.Password)
	}
}

// TestSessions_CookieTokenCapture verifies that an auth cookie set by the
// upstream is captured into the session's cookie tokens.
func TestSessions_CookieTokenCapture(t *testing.T) {
	harness := test.NewHarness(t)

	harness.UpstreamMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Set cookie with the original upstream domain so CookieRewriter rewrites
		// it to the phishing domain before TokenExtractor inspects it.
		http.SetCookie(w, &http.Cookie{
			Name:   "session",
			Value:  "tok-abc123",
			Domain: ".testsite.internal",
		})
		fmt.Fprint(w, "ok")
	})

	test.DrainAndClose(harness.VictimGet(t, "/"))

	sessions, err := harness.API.ListSessions(sdk.SessionFilter{})
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if sessions.Total != 1 {
		t.Fatalf("expected 1 session, got %d", sessions.Total)
	}
	sess := sessions.Items[0]
	found := false
	for _, byName := range sess.CookieTokens {
		if _, ok := byName["session"]; ok {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'session' cookie token to be captured; got tokens: %v", sess.CookieTokens)
	}
}

// TestSessions_CompletesWhenRequiredTokenCaptured verifies that a session is
// marked complete once the required auth cookie is captured.
func TestSessions_CompletesWhenRequiredTokenCaptured(t *testing.T) {
	harness := test.NewHarness(t)

	harness.UpstreamMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:   "session",
			Value:  "tok-abc123",
			Domain: ".testsite.internal",
		})
		fmt.Fprint(w, "ok")
	})

	test.DrainAndClose(harness.VictimGet(t, "/"))

	sessions, err := harness.API.ListSessions(sdk.SessionFilter{})
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if sessions.Total != 1 {
		t.Fatalf("expected 1 session, got %d", sessions.Total)
	}
	if sessions.Items[0].CompletedAt == nil {
		t.Error("expected session to be complete after required token captured, but CompletedAt is nil")
	}
}

// TestSessions_RemainsOpenWithoutRequiredToken verifies that a session stays
// open when the upstream does not set the required auth cookie.
func TestSessions_RemainsOpenWithoutRequiredToken(t *testing.T) {
	harness := test.NewHarness(t)

	harness.UpstreamMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Set an unrequired cookie — should not trigger completion.
		http.SetCookie(w, &http.Cookie{Name: "analytics", Value: "xyz"})
		fmt.Fprint(w, "ok")
	})

	test.DrainAndClose(harness.VictimGet(t, "/"))

	sessions, err := harness.API.ListSessions(sdk.SessionFilter{})
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if sessions.Total != 1 {
		t.Fatalf("expected 1 session, got %d", sessions.Total)
	}
	if sessions.Items[0].CompletedAt != nil {
		t.Error("expected session to remain open, but CompletedAt is set")
	}
}
