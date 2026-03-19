package request_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/proxy"
	"github.com/travisbale/mirage/internal/proxy/handlers/request"
)

// compiledLure builds a Lure with its UA regex pre-compiled.
func compiledLure(uaFilter string) *aitm.Lure {
	l := &aitm.Lure{UAFilter: uaFilter}
	if err := l.CompileUA(); err != nil {
		panic(err)
	}
	return l
}

func TestSessionGate_ExistingCookie_LoadsSession_SkipsLureChecks(t *testing.T) {
	existing := &aitm.Session{ID: "existing-sess"}
	spoofer := &stubSpoofer{}
	h := &request.SessionGate{
		Sessions: &stubSessionManager{getSession: existing},
		Spoof:    spoofer,
	}
	ctx := &aitm.ProxyContext{} // no Lure — would be spoofed for a new visitor
	req := newReq(http.MethodGet, "https://example.com/dashboard", nil)
	req.AddCookie(&http.Cookie{Name: "__ss", Value: "existing-sess"})

	if err := h.Handle(ctx, req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ctx.Session != existing {
		t.Error("expected existing session to be loaded")
	}
	if ctx.IsNewSession {
		t.Error("expected IsNewSession=false for existing session")
	}
	if spoofer.called {
		t.Error("expected spoofer not to be called for established session")
	}
}

func TestSessionGate_NoLure_Spoofs(t *testing.T) {
	spoofer := &stubSpoofer{}
	h := &request.SessionGate{
		Sessions: &stubSessionManager{newSession: &aitm.Session{ID: "new"}},
		Spoof:    spoofer,
	}
	ctx := &aitm.ProxyContext{ResponseWriter: httptest.NewRecorder()}
	req := newReq(http.MethodGet, "https://example.com/random", nil)

	if err := h.Handle(ctx, req); !errors.Is(err, proxy.ErrShortCircuit) {
		t.Fatalf("expected ErrShortCircuit, got %v", err)
	}
	if !spoofer.called {
		t.Error("expected spoofer to be called when no lure matches")
	}
	if ctx.Session != nil {
		t.Error("expected no session to be created for spoofed request")
	}
}

func TestSessionGate_PausedLure_Spoofs(t *testing.T) {
	spoofer := &stubSpoofer{}
	h := &request.SessionGate{
		Sessions: &stubSessionManager{newSession: &aitm.Session{ID: "new"}},
		Spoof:    spoofer,
	}
	ctx := &aitm.ProxyContext{
		Lure:           &aitm.Lure{PausedUntil: time.Now().Add(time.Hour)},
		ResponseWriter: httptest.NewRecorder(),
	}
	req := newReq(http.MethodGet, "https://example.com/lure123", nil)

	if err := h.Handle(ctx, req); !errors.Is(err, proxy.ErrShortCircuit) {
		t.Fatalf("expected ErrShortCircuit, got %v", err)
	}
	if !spoofer.called {
		t.Error("expected spoofer to be called for paused lure")
	}
	if ctx.Session != nil {
		t.Error("expected no session to be created for paused lure")
	}
}

func TestSessionGate_UAFilterNoMatch_Spoofs(t *testing.T) {
	spoofer := &stubSpoofer{}
	h := &request.SessionGate{
		Sessions: &stubSessionManager{newSession: &aitm.Session{ID: "new"}},
		Spoof:    spoofer,
	}
	ctx := &aitm.ProxyContext{
		Lure:           compiledLure("Mozilla"),
		ResponseWriter: httptest.NewRecorder(),
	}
	req := newReq(http.MethodGet, "https://example.com/lure123", nil)
	req.Header.Set("User-Agent", "Googlebot/2.1")

	if err := h.Handle(ctx, req); !errors.Is(err, proxy.ErrShortCircuit) {
		t.Fatalf("expected ErrShortCircuit, got %v", err)
	}
	if !spoofer.called {
		t.Error("expected spoofer to be called for UA filter mismatch")
	}
	if ctx.Session != nil {
		t.Error("expected no session to be created for UA mismatch")
	}
}

func TestSessionGate_ValidLure_CreatesSession(t *testing.T) {
	newSess := &aitm.Session{ID: "new-sess"}
	h := &request.SessionGate{
		Sessions: &stubSessionManager{newSession: newSess},
		Spoof:    &stubSpoofer{},
	}
	ctx := &aitm.ProxyContext{Lure: compiledLure("Mozilla")}
	req := newReq(http.MethodGet, "https://example.com/lure123", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0)")

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

func TestSessionGate_CompletedSession_RedirectsToLureURL(t *testing.T) {
	now := time.Now()
	completedSess := &aitm.Session{ID: "done-sess", CompletedAt: &now}
	h := &request.SessionGate{
		Sessions: &stubSessionManager{getSession: completedSess},
		Spoof:    &stubSpoofer{},
	}
	rec := httptest.NewRecorder()
	ctx := &aitm.ProxyContext{
		Lure:           &aitm.Lure{RedirectURL: "https://real-site.com/dashboard"},
		ResponseWriter: rec,
	}
	req := newReq(http.MethodGet, "https://login.phish.local/dashboard", nil)
	req.AddCookie(&http.Cookie{Name: "__ss", Value: "done-sess"})

	err := h.Handle(ctx, req)
	if !errors.Is(err, proxy.ErrShortCircuit) {
		t.Fatalf("expected ErrShortCircuit for completed session, got %v", err)
	}
	if rec.Code != http.StatusFound {
		t.Errorf("expected 302, got %d", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != "https://real-site.com/dashboard" {
		t.Errorf("Location = %q, want %q", got, "https://real-site.com/dashboard")
	}
}

func TestSessionGate_CompletedSession_NoLure_ContinuesNormally(t *testing.T) {
	now := time.Now()
	completedSess := &aitm.Session{ID: "done-sess", CompletedAt: &now}
	h := &request.SessionGate{
		Sessions: &stubSessionManager{getSession: completedSess},
		Spoof:    &stubSpoofer{},
	}
	ctx := &aitm.ProxyContext{} // no Lure
	req := newReq(http.MethodGet, "https://login.phish.local/dashboard", nil)
	req.AddCookie(&http.Cookie{Name: "__ss", Value: "done-sess"})

	if err := h.Handle(ctx, req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ctx.Session != completedSess {
		t.Error("expected session to be loaded even without lure redirect")
	}
}

func TestSessionGate_SessionFactoryError_ReturnsError(t *testing.T) {
	h := &request.SessionGate{
		Sessions: &stubSessionManager{newErr: errors.New("db down")},
		Spoof:    &stubSpoofer{},
	}
	ctx := &aitm.ProxyContext{Lure: compiledLure("")}
	req := newReq(http.MethodGet, "https://example.com/lure123", nil)

	if err := h.Handle(ctx, req); err == nil {
		t.Fatal("expected error from factory failure, got nil")
	}
}
