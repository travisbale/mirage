package request_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/proxy"
	"github.com/travisbale/mirage/internal/proxy/handlers/request"
)

func TestAPIRouter_MatchingHost_DelegatesToHandler(t *testing.T) {
	handler := &stubSpoofer{}
	h := &request.APIRouter{
		SecretHostname: "api-secret.example.com",
		Handler:        handler,
	}
	ctx := &aitm.ProxyContext{ResponseWriter: httptest.NewRecorder()}
	req := newReq(http.MethodGet, "https://api-secret.example.com/sessions", nil)
	req.Host = "api-secret.example.com"

	err := h.Handle(ctx, req)
	if !errors.Is(err, proxy.ErrShortCircuit) {
		t.Fatalf("expected ErrShortCircuit, got %v", err)
	}
	if !handler.called {
		t.Error("expected API handler to be called")
	}
}

func TestAPIRouter_CaseInsensitiveMatch(t *testing.T) {
	handler := &stubSpoofer{}
	h := &request.APIRouter{
		SecretHostname: "API-Secret.Example.Com",
		Handler:        handler,
	}
	ctx := &aitm.ProxyContext{ResponseWriter: httptest.NewRecorder()}
	req := newReq(http.MethodGet, "https://api-secret.example.com/sessions", nil)
	req.Host = "api-secret.example.com"

	err := h.Handle(ctx, req)
	if !errors.Is(err, proxy.ErrShortCircuit) {
		t.Fatalf("expected ErrShortCircuit for case-insensitive match, got %v", err)
	}
	if !handler.called {
		t.Error("expected handler to be called with case-insensitive match")
	}
}

func TestAPIRouter_HostWithPort_StripsPort(t *testing.T) {
	handler := &stubSpoofer{}
	h := &request.APIRouter{
		SecretHostname: "api-secret.example.com",
		Handler:        handler,
	}
	ctx := &aitm.ProxyContext{ResponseWriter: httptest.NewRecorder()}
	req := newReq(http.MethodGet, "https://api-secret.example.com:8443/sessions", nil)
	req.Host = "api-secret.example.com:8443"

	err := h.Handle(ctx, req)
	if !errors.Is(err, proxy.ErrShortCircuit) {
		t.Fatalf("expected ErrShortCircuit when host includes port, got %v", err)
	}
	if !handler.called {
		t.Error("expected API handler to be called when host includes port")
	}
}

func TestAPIRouter_NonMatchingHost_Passes(t *testing.T) {
	handler := &stubSpoofer{}
	h := &request.APIRouter{
		SecretHostname: "api-secret.example.com",
		Handler:        handler,
	}
	ctx := &aitm.ProxyContext{}
	req := newReq(http.MethodGet, "https://login.phish.example.com/", nil)
	req.Host = "login.phish.example.com"

	if err := h.Handle(ctx, req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if handler.called {
		t.Error("expected API handler NOT to be called for non-matching host")
	}
}
