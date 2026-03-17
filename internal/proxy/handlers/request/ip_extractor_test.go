package request_test

import (
	"net"
	"net/http"
	"testing"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/proxy/handlers/request"
)

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
