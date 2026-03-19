package response_test

import (
	"io"
	"net/http"
	"regexp"
	"testing"
	"time"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/proxy/handlers/response"
)

type stubSessionCompleter struct {
	updated          *aitm.Session
	completed        bool
	isCompleteResult bool // controls what IsComplete returns
	err              error
}

func (s *stubSessionCompleter) Update(sess *aitm.Session) error {
	s.updated = sess
	return s.err
}

func (s *stubSessionCompleter) Complete(_ *aitm.Session) error {
	s.completed = true
	return s.err
}

func (s *stubSessionCompleter) IsComplete(_ *aitm.Session, _ *aitm.Phishlet) bool {
	return s.isCompleteResult
}

type stubWhitelister struct{ ip string }

func (s *stubWhitelister) WhitelistTemporary(ip string, _ time.Duration) { s.ip = ip }

func TestTokenExtractor_CapturesCookieToken(t *testing.T) {
	sessions := &stubSessionCompleter{isCompleteResult: false}
	h := &response.TokenExtractor{
		Sessions: sessions,
		Logger:   discardLogger(),
	}
	resp := newResp(http.StatusOK, "text/html", "")
	resp.Header.Add("Set-Cookie", "authToken=secret; Domain=login.microsoft.com; Path=/")

	ctx := &aitm.ProxyContext{
		Session: &aitm.Session{ID: "sess-1"},
		Phishlet: &aitm.Phishlet{
			AuthTokens: []aitm.TokenRule{
				{Type: aitm.TokenTypeCookie, Name: regexp.MustCompile(`^authToken$`)},
			},
		},
	}

	if err := h.Handle(ctx, resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sessions.updated == nil {
		t.Fatal("expected session to be updated after token capture")
	}
	if _, ok := ctx.Session.CookieTokens["login.microsoft.com"]["authToken"]; !ok {
		t.Errorf("expected authToken captured, got: %v", ctx.Session.CookieTokens)
	}
}

func TestTokenExtractor_NoPhishlet_Skips(t *testing.T) {
	sessions := &stubSessionCompleter{}
	h := &response.TokenExtractor{
		Sessions: sessions,
		Logger:   discardLogger(),
	}
	resp := newResp(http.StatusOK, "text/html", "")
	resp.Header.Add("Set-Cookie", "tok=x; Path=/")

	if err := h.Handle(&aitm.ProxyContext{}, resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sessions.updated != nil {
		t.Error("expected no store update when phishlet is nil")
	}
}

func TestTokenExtractor_SessionCompleted(t *testing.T) {
	sessions := &stubSessionCompleter{isCompleteResult: true}
	whitelister := &stubWhitelister{}
	h := &response.TokenExtractor{
		Sessions:  sessions,
		Whitelist: whitelister,
		Logger:    discardLogger(),
	}
	resp := newResp(http.StatusOK, "text/html", "")
	ctx := &aitm.ProxyContext{
		ClientIP: "1.2.3.4",
		Session:  &aitm.Session{ID: "sess-1"},
		Phishlet: &aitm.Phishlet{},
	}

	if err := h.Handle(ctx, resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !sessions.completed {
		t.Error("expected Complete to be called on session completion")
	}
	if whitelister.ip != "1.2.3.4" {
		t.Errorf("expected IP 1.2.3.4 to be whitelisted, got %q", whitelister.ip)
	}
}

// TestTokenExtractor_DottedDomainRule verifies that an auth_token rule with a
// leading-dot domain (e.g. ".target.local") matches both the apex domain and
// subdomains, which is the standard phishlet authoring convention.
func TestTokenExtractor_DottedDomainRule(t *testing.T) {
	cases := []struct {
		cookieDomain string
		ruleDomain   string
		wantCapture  bool
	}{
		{".target.local", ".target.local", true},      // apex with leading dots on both
		{"target.local", ".target.local", true},       // apex, no leading dot on cookie
		{"login.target.local", ".target.local", true}, // subdomain matches dotted rule
		{".other.local", ".target.local", false},      // different domain
	}
	for _, tc := range cases {
		sessions := &stubSessionCompleter{}
		h := &response.TokenExtractor{Sessions: sessions, Logger: discardLogger()}
		resp := newResp(http.StatusOK, "text/html", "")
		resp.Header.Add("Set-Cookie", "tok=v; Domain="+tc.cookieDomain+"; Path=/")
		ctx := &aitm.ProxyContext{
			Session: &aitm.Session{ID: "s"},
			Phishlet: &aitm.Phishlet{
				AuthTokens: []aitm.TokenRule{
					{Type: aitm.TokenTypeCookie, Domain: tc.ruleDomain},
				},
			},
		}
		if err := h.Handle(ctx, resp); err != nil {
			t.Fatalf("cookie=%q rule=%q: unexpected error: %v", tc.cookieDomain, tc.ruleDomain, err)
		}
		captured := sessions.updated != nil
		if captured != tc.wantCapture {
			t.Errorf("cookie=%q rule=%q: captured=%v, want %v", tc.cookieDomain, tc.ruleDomain, captured, tc.wantCapture)
		}
	}
}

func TestTokenExtractor_CapturesHeaderToken(t *testing.T) {
	sessions := &stubSessionCompleter{isCompleteResult: false}
	h := &response.TokenExtractor{
		Sessions: sessions,
		Logger:   discardLogger(),
	}
	resp := newResp(http.StatusOK, "application/json", `{"ok":true}`)
	resp.Header.Set("X-Auth-Token", "Bearer abc123")

	ctx := &aitm.ProxyContext{
		Session: &aitm.Session{ID: "sess-1"},
		Phishlet: &aitm.Phishlet{
			AuthTokens: []aitm.TokenRule{
				{Type: aitm.TokenTypeHTTPHeader, Name: regexp.MustCompile(`^X-Auth-Token$`), Search: regexp.MustCompile(`Bearer (.+)`)},
			},
		},
	}

	if err := h.Handle(ctx, resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sessions.updated == nil {
		t.Fatal("expected session to be updated after header token capture")
	}
	if got := ctx.Session.HTTPTokens["X-Auth-Token"]; got != "abc123" {
		t.Errorf("HTTPTokens[X-Auth-Token] = %q, want %q", got, "abc123")
	}
}

func TestTokenExtractor_HeaderToken_NoSearchGroup_CapturesFullValue(t *testing.T) {
	sessions := &stubSessionCompleter{isCompleteResult: false}
	h := &response.TokenExtractor{
		Sessions: sessions,
		Logger:   discardLogger(),
	}
	resp := newResp(http.StatusOK, "text/html", "")
	resp.Header.Set("X-Request-Id", "raw-value-123")

	ctx := &aitm.ProxyContext{
		Session: &aitm.Session{ID: "sess-1"},
		Phishlet: &aitm.Phishlet{
			AuthTokens: []aitm.TokenRule{
				// Go canonicalizes header names, so "X-Request-Id" becomes "X-Request-Id"
				{Type: aitm.TokenTypeHTTPHeader, Name: regexp.MustCompile(`^X-Request-Id$`)},
			},
		},
	}

	if err := h.Handle(ctx, resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := ctx.Session.HTTPTokens["X-Request-Id"]; got != "raw-value-123" {
		t.Errorf("HTTPTokens[X-Request-Id] = %q, want %q", got, "raw-value-123")
	}
}

func TestTokenExtractor_HeaderToken_SearchNoMatch_Skips(t *testing.T) {
	sessions := &stubSessionCompleter{isCompleteResult: false}
	h := &response.TokenExtractor{
		Sessions: sessions,
		Logger:   discardLogger(),
	}
	resp := newResp(http.StatusOK, "text/html", "")
	resp.Header.Set("X-Auth-Token", "Basic notbearer")

	ctx := &aitm.ProxyContext{
		Session: &aitm.Session{ID: "sess-1"},
		Phishlet: &aitm.Phishlet{
			AuthTokens: []aitm.TokenRule{
				{Type: aitm.TokenTypeHTTPHeader, Name: regexp.MustCompile(`^X-Auth-Token$`), Search: regexp.MustCompile(`Bearer (.+)`)},
			},
		},
	}

	if err := h.Handle(ctx, resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sessions.updated != nil {
		t.Error("expected no update when search regex doesn't match")
	}
}

func TestTokenExtractor_CapturesBodyToken(t *testing.T) {
	sessions := &stubSessionCompleter{isCompleteResult: false}
	h := &response.TokenExtractor{
		Sessions: sessions,
		Logger:   discardLogger(),
	}
	body := `{"access_token": "tok_abc123", "token_type": "bearer"}`
	resp := newResp(http.StatusOK, "application/json", body)

	ctx := &aitm.ProxyContext{
		Session: &aitm.Session{ID: "sess-1"},
		Phishlet: &aitm.Phishlet{
			AuthTokens: []aitm.TokenRule{
				{Type: aitm.TokenTypeBody, Name: regexp.MustCompile(`access_token`), Search: regexp.MustCompile(`"access_token"\s*:\s*"([^"]+)"`)},
			},
		},
	}

	if err := h.Handle(ctx, resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sessions.updated == nil {
		t.Fatal("expected session to be updated after body token capture")
	}
	if got := ctx.Session.BodyTokens["access_token"]; got != "tok_abc123" {
		t.Errorf("BodyTokens[access_token] = %q, want %q", got, "tok_abc123")
	}
}

func TestTokenExtractor_BodyToken_BinaryResponse_Skips(t *testing.T) {
	sessions := &stubSessionCompleter{isCompleteResult: false}
	h := &response.TokenExtractor{
		Sessions: sessions,
		Logger:   discardLogger(),
	}
	resp := newResp(http.StatusOK, "image/png", "\x89PNG\r\n")

	ctx := &aitm.ProxyContext{
		Session: &aitm.Session{ID: "sess-1"},
		Phishlet: &aitm.Phishlet{
			AuthTokens: []aitm.TokenRule{
				{Type: aitm.TokenTypeBody, Name: regexp.MustCompile(`token`), Search: regexp.MustCompile(`"token":"([^"]+)"`)},
			},
		},
	}

	if err := h.Handle(ctx, resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sessions.updated != nil {
		t.Error("expected no update for binary content type")
	}
}

func TestTokenExtractor_BodyToken_NoSearchMatch_Skips(t *testing.T) {
	sessions := &stubSessionCompleter{isCompleteResult: false}
	h := &response.TokenExtractor{
		Sessions: sessions,
		Logger:   discardLogger(),
	}
	body := `{"error": "unauthorized"}`
	resp := newResp(http.StatusOK, "application/json", body)

	ctx := &aitm.ProxyContext{
		Session: &aitm.Session{ID: "sess-1"},
		Phishlet: &aitm.Phishlet{
			AuthTokens: []aitm.TokenRule{
				{Type: aitm.TokenTypeBody, Name: regexp.MustCompile(`access_token`), Search: regexp.MustCompile(`"access_token"\s*:\s*"([^"]+)"`)},
			},
		},
	}

	if err := h.Handle(ctx, resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sessions.updated != nil {
		t.Error("expected no update when body doesn't match search regex")
	}
}

func TestTokenExtractor_BodyToken_PreservesBodyForDownstreamHandlers(t *testing.T) {
	sessions := &stubSessionCompleter{isCompleteResult: false}
	h := &response.TokenExtractor{
		Sessions: sessions,
		Logger:   discardLogger(),
	}
	body := `{"access_token": "tok_123"}`
	resp := newResp(http.StatusOK, "application/json", body)

	ctx := &aitm.ProxyContext{
		Session: &aitm.Session{ID: "sess-1"},
		Phishlet: &aitm.Phishlet{
			AuthTokens: []aitm.TokenRule{
				{Type: aitm.TokenTypeBody, Name: regexp.MustCompile(`access_token`), Search: regexp.MustCompile(`"access_token"\s*:\s*"([^"]+)"`)},
			},
		},
	}

	if err := h.Handle(ctx, resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Body should still be readable by downstream handlers (SubFilterApplier, etc.)
	remaining, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read body after extraction: %v", err)
	}
	if string(remaining) != body {
		t.Errorf("body after extraction = %q, want %q", string(remaining), body)
	}
}

func TestTokenExtractor_SessionCompleted_NilWhitelist(t *testing.T) {
	sessions := &stubSessionCompleter{isCompleteResult: true}
	h := &response.TokenExtractor{
		Sessions:  sessions,
		Whitelist: nil, // no whitelist configured — must not panic
		Logger:    discardLogger(),
	}
	resp := newResp(http.StatusOK, "text/html", "")
	ctx := &aitm.ProxyContext{
		ClientIP: "1.2.3.4",
		Session:  &aitm.Session{ID: "sess-1"},
		Phishlet: &aitm.Phishlet{},
	}

	if err := h.Handle(ctx, resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !sessions.completed {
		t.Error("expected Complete to be called even with nil Whitelist")
	}
}
