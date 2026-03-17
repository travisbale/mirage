package request_test

import (
	"net/http"
	"testing"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/proxy/handlers/request"
)

type stubOverrideSource struct {
	overrides map[string]string
}

func (s *stubOverrideSource) GetOverride(phishletName string) string {
	return s.overrides[phishletName]
}

func TestPuppetOverrideResolver_SetsOverride(t *testing.T) {
	h := &request.PuppetOverrideResolver{
		Source: &stubOverrideSource{overrides: map[string]string{
			"microsoft": "(function(){/*ms*/})();",
		}},
	}
	ctx := &aitm.ProxyContext{Phishlet: &aitm.Phishlet{Name: "microsoft"}}
	req := newReq(http.MethodGet, "https://login.example.com/", nil)

	if err := h.Handle(ctx, req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ctx.PuppetOverride != "(function(){/*ms*/})();" {
		t.Errorf("got %q, want override script", ctx.PuppetOverride)
	}
}

func TestPuppetOverrideResolver_NoCachedOverride(t *testing.T) {
	h := &request.PuppetOverrideResolver{
		Source: &stubOverrideSource{overrides: map[string]string{}},
	}
	ctx := &aitm.ProxyContext{Phishlet: &aitm.Phishlet{Name: "google"}}
	req := newReq(http.MethodGet, "https://accounts.example.com/", nil)

	if err := h.Handle(ctx, req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ctx.PuppetOverride != "" {
		t.Errorf("expected empty override, got %q", ctx.PuppetOverride)
	}
}

func TestPuppetOverrideResolver_NilSource(t *testing.T) {
	h := &request.PuppetOverrideResolver{Source: nil}
	ctx := &aitm.ProxyContext{Phishlet: &aitm.Phishlet{Name: "microsoft"}}
	req := newReq(http.MethodGet, "https://login.example.com/", nil)

	if err := h.Handle(ctx, req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ctx.PuppetOverride != "" {
		t.Errorf("expected empty override with nil source, got %q", ctx.PuppetOverride)
	}
}

func TestPuppetOverrideResolver_NilPhishlet(t *testing.T) {
	h := &request.PuppetOverrideResolver{
		Source: &stubOverrideSource{overrides: map[string]string{"x": "y"}},
	}
	ctx := &aitm.ProxyContext{} // no Phishlet
	req := newReq(http.MethodGet, "https://example.com/", nil)

	if err := h.Handle(ctx, req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ctx.PuppetOverride != "" {
		t.Errorf("expected empty override with nil phishlet, got %q", ctx.PuppetOverride)
	}
}
