package request_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/proxy"
	"github.com/travisbale/mirage/internal/proxy/handlers/request"
)

func TestInterceptHandler_MatchingPath_ReturnsCustomResponse(t *testing.T) {
	h := &request.InterceptHandler{}
	rec := httptest.NewRecorder()
	ctx := &aitm.ProxyContext{
		Phishlet: &aitm.Phishlet{
			Intercepts: []aitm.InterceptRule{{
				Path:        regexp.MustCompile(`^/api/telemetry$`),
				StatusCode:  200,
				ContentType: "application/json",
				Body:        `{"status":"ok"}`,
			}},
		},
		ResponseWriter: rec,
	}
	req := newReq(http.MethodPost, "https://login.phish.local/api/telemetry", strings.NewReader(`{"ua":"test"}`))

	err := h.Handle(ctx, req)
	if !errors.Is(err, proxy.ErrShortCircuit) {
		t.Fatalf("expected ErrShortCircuit, got %v", err)
	}
	if rec.Code != 200 {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want %q", got, "application/json")
	}
	if got := rec.Body.String(); got != `{"status":"ok"}` {
		t.Errorf("body = %q, want %q", got, `{"status":"ok"}`)
	}
}

func TestInterceptHandler_NonMatchingPath_PassesThrough(t *testing.T) {
	h := &request.InterceptHandler{}
	ctx := &aitm.ProxyContext{
		Phishlet: &aitm.Phishlet{
			Intercepts: []aitm.InterceptRule{{
				Path:       regexp.MustCompile(`^/api/telemetry$`),
				StatusCode: 200,
			}},
		},
	}
	req := newReq(http.MethodGet, "https://login.phish.local/dashboard", nil)

	if err := h.Handle(ctx, req); err != nil {
		t.Fatalf("expected nil error for non-matching path, got %v", err)
	}
}

func TestInterceptHandler_BodySearchMatch_Intercepts(t *testing.T) {
	h := &request.InterceptHandler{}
	rec := httptest.NewRecorder()
	ctx := &aitm.ProxyContext{
		Phishlet: &aitm.Phishlet{
			Intercepts: []aitm.InterceptRule{{
				Path:        regexp.MustCompile(`^/api/check$`),
				BodySearch:  regexp.MustCompile(`"supported"\s*:\s*true`),
				StatusCode:  200,
				ContentType: "application/json",
				Body:        `{"ok":true}`,
			}},
		},
		ResponseWriter: rec,
	}
	req := newReq(http.MethodPost, "https://login.phish.local/api/check", strings.NewReader(`{"supported": true}`))

	err := h.Handle(ctx, req)
	if !errors.Is(err, proxy.ErrShortCircuit) {
		t.Fatalf("expected ErrShortCircuit, got %v", err)
	}
}

func TestInterceptHandler_BodySearchNoMatch_PassesThrough(t *testing.T) {
	h := &request.InterceptHandler{}
	ctx := &aitm.ProxyContext{
		Phishlet: &aitm.Phishlet{
			Intercepts: []aitm.InterceptRule{{
				Path:       regexp.MustCompile(`^/api/check$`),
				BodySearch: regexp.MustCompile(`"supported"\s*:\s*true`),
				StatusCode: 200,
			}},
		},
	}
	req := newReq(http.MethodPost, "https://login.phish.local/api/check", strings.NewReader(`{"supported": false}`))

	if err := h.Handle(ctx, req); err != nil {
		t.Fatalf("expected nil for non-matching body, got %v", err)
	}
}

func TestInterceptHandler_NilPhishlet_PassesThrough(t *testing.T) {
	h := &request.InterceptHandler{}
	ctx := &aitm.ProxyContext{}
	req := newReq(http.MethodGet, "https://example.com/anything", nil)

	if err := h.Handle(ctx, req); err != nil {
		t.Fatalf("expected nil for nil phishlet, got %v", err)
	}
}
