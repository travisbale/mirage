package request_test

import (
	"net/http"
	"testing"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/proxy/handlers/request"
)

func TestLureRedirector_NoLure_PassesThrough(t *testing.T) {
	h := &request.LureRedirector{}
	ctx := &aitm.ProxyContext{}
	req := newReq(http.MethodGet, "https://login.phish.example.com/abc123", nil)

	if err := h.Handle(ctx, req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.URL.Path != "/abc123" {
		t.Errorf("expected path unchanged, got %q", req.URL.Path)
	}
}

func TestLureRedirector_PathMismatch_PassesThrough(t *testing.T) {
	h := &request.LureRedirector{}
	ctx := &aitm.ProxyContext{
		Lure: &aitm.Lure{Path: "/abc123"},
	}
	req := newReq(http.MethodGet, "https://login.phish.example.com/other", nil)

	if err := h.Handle(ctx, req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.URL.Path != "/other" {
		t.Errorf("expected path unchanged, got %q", req.URL.Path)
	}
}

func TestLureRedirector_LurePathMatch_RewritesToLoginPath(t *testing.T) {
	h := &request.LureRedirector{}
	ctx := &aitm.ProxyContext{
		Lure:     &aitm.Lure{Path: "/abc123"},
		Phishlet: &aitm.Phishlet{Login: aitm.LoginSpec{Path: "/login"}},
	}
	req := newReq(http.MethodGet, "https://login.phish.example.com/abc123", nil)

	if err := h.Handle(ctx, req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.URL.Path != "/login" {
		t.Errorf("expected /login, got %q", req.URL.Path)
	}
}

func TestLureRedirector_NoPhishlet_RewritesToRoot(t *testing.T) {
	h := &request.LureRedirector{}
	ctx := &aitm.ProxyContext{
		Lure: &aitm.Lure{Path: "/abc123"},
	}
	req := newReq(http.MethodGet, "https://login.phish.example.com/abc123", nil)

	if err := h.Handle(ctx, req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.URL.Path != "/" {
		t.Errorf("expected /, got %q", req.URL.Path)
	}
}

func TestLureRedirector_EmptyLoginPath_RewritesToRoot(t *testing.T) {
	h := &request.LureRedirector{}
	ctx := &aitm.ProxyContext{
		Lure:     &aitm.Lure{Path: "/abc123"},
		Phishlet: &aitm.Phishlet{},
	}
	req := newReq(http.MethodGet, "https://login.phish.example.com/abc123", nil)

	if err := h.Handle(ctx, req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.URL.Path != "/" {
		t.Errorf("expected /, got %q", req.URL.Path)
	}
}
