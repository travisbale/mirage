package request_test

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

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
		Phishlet: &aitm.Phishlet{
			ProxyHosts: []aitm.ProxyHost{
				{PhishSubdomain: "login", OrigSubdomain: "login", Domain: "microsoft.com"},
			},
			BaseDomain: "phish.example.com",
		},
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

// ---- IPExtractor ------------------------------------------------------------

func mustCIDR(s string) *net.IPNet {
	_, cidr, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return cidr
}

func TestIPExtractor_DirectConnection(t *testing.T) {
	h := &request.IPExtractor{}
	ctx := &aitm.ProxyContext{}
	req := newReq(http.MethodGet, "https://example.com/", nil)
	req.RemoteAddr = "1.2.3.4:54321"

	if err := h.Handle(ctx, req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ctx.ClientIP != "1.2.3.4" {
		t.Errorf("expected 1.2.3.4, got %q", ctx.ClientIP)
	}
}

func TestIPExtractor_TrustedProxy_XForwardedFor(t *testing.T) {
	h := &request.IPExtractor{TrustedCIDRs: []*net.IPNet{mustCIDR("10.0.0.0/8")}}
	ctx := &aitm.ProxyContext{}
	req := newReq(http.MethodGet, "https://example.com/", nil)
	req.RemoteAddr = "10.0.0.1:443"
	req.Header.Set("X-Forwarded-For", "5.6.7.8, 10.0.0.1")

	if err := h.Handle(ctx, req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ctx.ClientIP != "5.6.7.8" {
		t.Errorf("expected 5.6.7.8 from XFF, got %q", ctx.ClientIP)
	}
}

func TestIPExtractor_UntrustedProxy_IgnoresHeader(t *testing.T) {
	h := &request.IPExtractor{TrustedCIDRs: []*net.IPNet{mustCIDR("10.0.0.0/8")}}
	ctx := &aitm.ProxyContext{}
	req := newReq(http.MethodGet, "https://example.com/", nil)
	req.RemoteAddr = "1.2.3.4:443" // not in trusted CIDR
	req.Header.Set("X-Forwarded-For", "9.9.9.9")

	if err := h.Handle(ctx, req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ctx.ClientIP != "1.2.3.4" {
		t.Errorf("expected socket IP 1.2.3.4, got %q", ctx.ClientIP)
	}
}

// ---- LureValidator ----------------------------------------------------------

func TestLureValidator_NoLure_Skips(t *testing.T) {
	h := &request.LureValidator{Spoof: &stubSpoofer{}}
	ctx := &aitm.ProxyContext{} // Lure is nil
	req := newReq(http.MethodGet, "https://example.com/", nil)
	if err := h.Handle(ctx, req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLureValidator_PausedLure_Spoofs(t *testing.T) {
	spoofer := &stubSpoofer{}
	h := &request.LureValidator{Spoof: spoofer}
	pausedUntil := time.Now().Add(time.Hour)
	ctx := &aitm.ProxyContext{
		Lure:           &aitm.Lure{PausedUntil: pausedUntil},
		ResponseWriter: httptest.NewRecorder(),
	}
	req := newReq(http.MethodGet, "https://example.com/", nil)
	if err := h.Handle(ctx, req); err != proxy.ErrShortCircuit {
		t.Fatalf("expected ErrShortCircuit, got %v", err)
	}
	if !spoofer.called {
		t.Error("expected spoofer to be called for paused lure")
	}
}

func compiledLure(uaFilter string) *aitm.Lure {
	l := &aitm.Lure{UAFilter: uaFilter}
	if err := l.CompileUA(); err != nil {
		panic(err)
	}
	return l
}

func TestLureValidator_UAFilterMatch_Passes(t *testing.T) {
	h := &request.LureValidator{Spoof: &stubSpoofer{}}
	ctx := &aitm.ProxyContext{Lure: compiledLure("Mozilla")}
	req := newReq(http.MethodGet, "https://example.com/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0)")
	if err := h.Handle(ctx, req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLureValidator_UAFilterNoMatch_Spoofs(t *testing.T) {
	spoofer := &stubSpoofer{}
	h := &request.LureValidator{Spoof: spoofer}
	ctx := &aitm.ProxyContext{
		Lure:           compiledLure("Mozilla"),
		ResponseWriter: httptest.NewRecorder(),
	}
	req := newReq(http.MethodGet, "https://example.com/", nil)
	req.Header.Set("User-Agent", "Googlebot/2.1")
	if err := h.Handle(ctx, req); err != proxy.ErrShortCircuit {
		t.Fatalf("expected ErrShortCircuit, got %v", err)
	}
	if !spoofer.called {
		t.Error("expected spoofer for UA filter mismatch")
	}
}

// ---- SessionResolver --------------------------------------------------------

type stubSessionManager struct {
	getSession *aitm.Session
	getErr     error
	newSession *aitm.Session
	newErr     error
}

func (s *stubSessionManager) Get(_ string) (*aitm.Session, error) {
	return s.getSession, s.getErr
}

func (s *stubSessionManager) NewSession(_ *aitm.ProxyContext) (*aitm.Session, error) {
	return s.newSession, s.newErr
}

func TestSessionResolver_ExistingSession_FromCookie(t *testing.T) {
	existing := &aitm.Session{ID: "existing-sess"}
	h := &request.SessionResolver{
		Sessions: &stubSessionManager{getSession: existing},
	}
	ctx := &aitm.ProxyContext{}
	req := newReq(http.MethodGet, "https://example.com/", nil)
	req.AddCookie(&http.Cookie{Name: "__ss", Value: "existing-sess"})

	if err := h.Handle(ctx, req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ctx.Session != existing {
		t.Error("expected existing session to be loaded from cookie")
	}
	if ctx.IsNewSession {
		t.Error("expected IsNewSession=false for existing session")
	}
}

func TestSessionResolver_NoCookie_CreatesNew(t *testing.T) {
	newSess := &aitm.Session{ID: "new-sess"}
	h := &request.SessionResolver{
		Sessions: &stubSessionManager{getErr: errors.New("not found"), newSession: newSess},
	}
	ctx := &aitm.ProxyContext{}
	req := newReq(http.MethodGet, "https://example.com/", nil)

	if err := h.Handle(ctx, req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ctx.Session != newSess {
		t.Error("expected new session to be created")
	}
	if !ctx.IsNewSession {
		t.Error("expected IsNewSession=true for new session")
	}
}

func TestSessionResolver_FactoryError_ReturnsError(t *testing.T) {
	h := &request.SessionResolver{
		Sessions: &stubSessionManager{getErr: errors.New("not found"), newErr: errors.New("db down")},
	}
	ctx := &aitm.ProxyContext{}
	req := newReq(http.MethodGet, "https://example.com/", nil)

	if err := h.Handle(ctx, req); err == nil {
		t.Fatal("expected error from factory failure, got nil")
	}
}

// ---- CredentialExtractor ----------------------------------------------------

type stubCredentialCapturer struct{}

func (s *stubCredentialCapturer) CaptureCredentials(_ *aitm.Session) error { return nil }

func TestCredentialExtractor_ExtractsUsername(t *testing.T) {
	h := &request.CredentialExtractor{
		Capturer: &stubCredentialCapturer{},
		Logger:   discardLogger(),
	}
	ctx := &aitm.ProxyContext{
		Session: &aitm.Session{ID: "sess-1"},
		Phishlet: &aitm.Phishlet{
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

func TestCredentialExtractor_NonPost_Skips(t *testing.T) {
	h := &request.CredentialExtractor{
		Capturer: &stubCredentialCapturer{},
		Logger:   discardLogger(),
	}
	ctx := &aitm.ProxyContext{
		Session:  &aitm.Session{ID: "sess-1"},
		Phishlet: &aitm.Phishlet{},
	}
	req := newReq(http.MethodGet, "https://login.example.com/", nil)
	if err := h.Handle(ctx, req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ctx.Session.Username != "" {
		t.Error("expected no extraction for non-POST request")
	}
}

func TestCredentialExtractor_NoPhishlet_Skips(t *testing.T) {
	h := &request.CredentialExtractor{
		Capturer: &stubCredentialCapturer{},
		Logger:   discardLogger(),
	}
	ctx := &aitm.ProxyContext{Session: &aitm.Session{ID: "sess-1"}} // no Phishlet
	req := newReq(http.MethodPost, "https://login.example.com/login", strings.NewReader("username=x"))
	if err := h.Handle(ctx, req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCredentialExtractor_NoRuleMatch_NoUpdate(t *testing.T) {
	h := &request.CredentialExtractor{
		Capturer: &stubCredentialCapturer{},
		Logger:   discardLogger(),
	}
	ctx := &aitm.ProxyContext{
		Session: &aitm.Session{ID: "sess-1"},
		Phishlet: &aitm.Phishlet{
			Credentials: aitm.CredentialRules{
				Username: aitm.CredentialRule{
					Key:  regexp.MustCompile(`^user$`),
					Type: "post",
				},
			},
		},
	}
	// Body has "login" key, not "user" — no match.
	req := newReq(http.MethodPost, "https://login.example.com/login", strings.NewReader("login=victim"))
	if err := h.Handle(ctx, req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ctx.Session.Username != "" {
		t.Error("expected no username extracted when key does not match")
	}
}
