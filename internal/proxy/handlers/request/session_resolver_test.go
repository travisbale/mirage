package request_test

import (
	"errors"
	"net/http"
	"testing"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/proxy/handlers/request"
)

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
