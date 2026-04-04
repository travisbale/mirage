package test_test

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/travisbale/mirage/sdk"
	"github.com/travisbale/mirage/test"
)

// TestSessions_CredentialExtraction verifies that a POST to the login path
// with form-encoded credentials results in the session recording them.
func TestSessions_CredentialExtraction(t *testing.T) {
	t.Parallel()
	harness := test.NewHarness(t)

	harness.UpstreamMux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Hit the lure path to establish a session and receive the tracking cookie.
	test.DrainAndClose(harness.VictimGet(t, "/"))

	// POST credentials to the login path (session cookie is now set in the jar).
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

// TestSessions_CookieTokenCapture verifies that an auth cookie set by the
// upstream is captured into the session's cookie tokens.
func TestSessions_CookieTokenCapture(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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

// TestSessions_ForcePostInjectsParam verifies that force_post injects
// the login_source=web parameter into login POSTs that contain an email field.
func TestSessions_ForcePostInjectsParam(t *testing.T) {
	t.Parallel()
	harness := test.NewHarness(t)

	var receivedLoginSource string
	harness.UpstreamMux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		receivedLoginSource = r.PostForm.Get("login_source")
		w.WriteHeader(http.StatusOK)
	})

	// Establish session.
	test.DrainAndClose(harness.VictimGet(t, "/"))

	// POST with email field — force_post condition matches, should inject login_source.
	test.DrainAndClose(harness.VictimPost(t, "/login", "email=alice%40example.com&password=s3cret"))

	if receivedLoginSource != "web" {
		t.Errorf("expected force_post to inject login_source=web, got %q", receivedLoginSource)
	}
}

// TestSessions_CompletedSessionRedirects verifies that a request from a
// completed session receives a 302 redirect to the lure's redirect URL
// instead of being proxied upstream.
func TestSessions_CompletedSessionRedirects(t *testing.T) {
	t.Parallel()
	harness := test.NewHarness(t)

	harness.UpstreamMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Set the required token so session completes on first request.
		http.SetCookie(w, &http.Cookie{
			Name:   "session",
			Value:  "tok-abc",
			Domain: ".testsite.internal",
		})
		fmt.Fprint(w, "ok")
	})

	// First request: session created + completed (required token captured).
	test.DrainAndClose(harness.VictimGet(t, "/"))

	// Second request: session is done, should get 302 to lure redirect URL.
	resp := harness.VictimGet(t, "/anything")
	defer test.DrainAndClose(resp)

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302 for completed session, got %d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if loc != "https://testsite.internal/" {
		t.Errorf("Location = %q, want %q", loc, "https://testsite.internal/")
	}
}

// TestSessions_FullLoginFlow simulates the complete form login:
// lure hit → login POST → MFA POST → session complete with credentials.
func TestSessions_FullLoginFlow(t *testing.T) {
	t.Parallel()
	harness := test.NewHarness(t)

	harness.UpstreamMux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			http.SetCookie(w, &http.Cookie{Name: "pending", Value: "tok"})
			http.Redirect(w, r, "/mfa", http.StatusFound)
			return
		}
		fmt.Fprint(w, "login page")
	})
	harness.UpstreamMux.HandleFunc("/mfa", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			// Set the required auth cookie — this triggers session completion.
			http.SetCookie(w, &http.Cookie{
				Name:   "session",
				Value:  "auth-tok-xyz",
				Domain: ".testsite.internal",
			})
			http.Redirect(w, r, "/dashboard", http.StatusFound)
			return
		}
		fmt.Fprint(w, "mfa page")
	})
	harness.UpstreamMux.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "dashboard")
	})

	// 1. Hit lure → session created.
	test.DrainAndClose(harness.VictimGet(t, "/"))

	// 2. POST login credentials.
	resp := harness.VictimPost(t, "/login", "email=alice%40example.com&password=s3cret")
	test.DrainAndClose(resp)

	// 3. Follow redirect to /mfa, then POST MFA code.
	test.DrainAndClose(harness.VictimGet(t, "/mfa"))
	resp = harness.VictimPost(t, "/mfa", "code=123456")
	test.DrainAndClose(resp)

	// 4. Verify session state.
	sessions, err := harness.API.ListSessions(sdk.SessionFilter{})
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if sessions.Total != 1 {
		t.Fatalf("expected 1 session, got %d", sessions.Total)
	}
	sess := sessions.Items[0]
	if sess.Username != "alice@example.com" {
		t.Errorf("Username = %q, want %q", sess.Username, "alice@example.com")
	}
	if sess.Password != "s3cret" {
		t.Errorf("Password = %q, want %q", sess.Password, "s3cret")
	}
	if sess.Custom == nil || sess.Custom["mfa_code"] != "123456" {
		t.Errorf("Custom[mfa_code] = %q, want %q", sess.Custom["mfa_code"], "123456")
	}
	if sess.CompletedAt == nil {
		t.Error("expected session to be complete")
	}
	// Verify auth cookie was captured.
	found := false
	for _, byName := range sess.CookieTokens {
		if _, ok := byName["session"]; ok {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected session cookie token to be captured")
	}
}

// TestSessions_StreamEvents verifies that StreamSessions delivers real-time
// events when a victim session is created and credentials are captured.
func TestSessions_StreamEvents(t *testing.T) {
	t.Parallel()
	harness := test.NewHarness(t)

	harness.UpstreamMux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			http.SetCookie(w, &http.Cookie{
				Name:   "session",
				Value:  "tok-stream",
				Domain: ".testsite.internal",
			})
			w.WriteHeader(http.StatusOK)
			return
		}
		fmt.Fprint(w, "login page")
	})

	// Open the SSE stream before triggering any sessions.
	ch, cancel, err := harness.API.StreamSessions()
	if err != nil {
		t.Fatalf("StreamSessions: %v", err)
	}
	defer cancel()

	// Wait for the initial "connected" event (not a session event).
	// The first real event will be a session.created when the victim hits the lure.

	// Trigger a session: victim hits lure then POSTs credentials.
	test.DrainAndClose(harness.VictimGet(t, "/"))
	test.DrainAndClose(harness.VictimPost(t, "/login", "username=alice&password=s3cret"))

	// Wait for a credential capture event.
	waitForEvent(t, ch, func(evt sdk.SessionEvent) bool {
		return evt.Type == sdk.EventCredsCaptured && evt.Session.Username == "alice"
	})
}

// TestSessions_LureURLParams verifies that encrypted URL parameters (?p=)
// are decrypted and stored on the session's LureParams field when a victim clicks.
func TestSessions_LureURLParams(t *testing.T) {
	t.Parallel()
	harness := test.NewHarness(t)

	harness.UpstreamMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	})

	// Create a lure with a specific path for this test.
	lure, err := harness.API.CreateLure(sdk.CreateLureRequest{
		Phishlet:    "testsite",
		Path:        "/track",
		RedirectURL: "https://testsite.internal/",
	})
	if err != nil {
		t.Fatalf("CreateLure: %v", err)
	}

	// Generate a URL with custom tracking params.
	urlResp, err := harness.API.GenerateLureURL(lure.ID, sdk.GenerateURLRequest{
		Params: map[string]string{"t": "result-abc", "campaign": "test-campaign"},
	})
	if err != nil {
		t.Fatalf("GenerateLureURL: %v", err)
	}

	// Victim clicks the tracked URL.
	// Extract the path+query from the full URL to use with VictimGet.
	trackedURL := urlResp.URL
	// The URL looks like https://login.phish.test/track?p=<encrypted>
	// We need to visit it through the proxy.
	req, err := http.NewRequest(http.MethodGet, trackedURL, nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	resp, err := harness.Victim.Do(req)
	if err != nil {
		t.Fatalf("victim GET tracked URL: %v", err)
	}
	test.DrainAndClose(resp)

	// Verify the session has the decrypted params in LureParams.
	sessions, err := harness.API.ListSessions(sdk.SessionFilter{})
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}

	// Find the session created by the tracked lure hit (not the default lure).
	var found bool
	for _, sess := range sessions.Items {
		if sess.LureParams != nil && sess.LureParams["t"] == "result-abc" {
			if sess.LureParams["campaign"] != "test-campaign" {
				t.Errorf("LureParams[campaign] = %q, want %q", sess.LureParams["campaign"], "test-campaign")
			}
			found = true
			break
		}
	}
	if !found {
		t.Error("expected session with LureParams from tracked lure URL")
	}
}

// waitForEvent reads from the SSE channel until match returns true or a timeout fires.
func waitForEvent(t *testing.T, ch <-chan sdk.SessionEvent, match func(sdk.SessionEvent) bool) {
	t.Helper()
	timeout := time.After(5 * time.Second)
	for {
		select {
		case evt, ok := <-ch:
			if !ok {
				t.Fatal("stream closed unexpectedly")
			}
			if match(evt) {
				return
			}
		case <-timeout:
			t.Fatal("timed out waiting for matching session event")
		}
	}
}
