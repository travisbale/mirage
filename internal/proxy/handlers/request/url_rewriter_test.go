package request_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/proxy/handlers/request"
)

func TestURLRewriter_RewritesHostname(t *testing.T) {
	h := &request.URLRewriter{}
	ctx := &aitm.ProxyContext{
		Phishlet: &aitm.Phishlet{
			ProxyHosts: []aitm.ProxyHost{
				{PhishSubdomain: "login", OrigSubdomain: "login", Domain: "microsoft.com", UpstreamScheme: "https"},
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
	if req.URL.Scheme != "https" {
		t.Errorf("expected scheme https, got %q", req.URL.Scheme)
	}
}

func TestURLRewriter_HostWithPort_StillRewrites(t *testing.T) {
	h := &request.URLRewriter{}
	ctx := &aitm.ProxyContext{
		Phishlet: &aitm.Phishlet{
			ProxyHosts: []aitm.ProxyHost{
				{PhishSubdomain: "login", OrigSubdomain: "login", Domain: "microsoft.com", UpstreamScheme: "https"},
			},
			BaseDomain: "phish.example.com",
		},
	}
	req := newReq(http.MethodGet, "https://login.phish.example.com:8443/oauth2", nil)
	req.Host = "login.phish.example.com:8443"

	if err := h.Handle(ctx, req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(req.URL.Host, "microsoft.com") {
		t.Errorf("expected URL host rewritten to microsoft.com when host includes port, got %q", req.URL.Host)
	}
}

func TestURLRewriter_HTTPUpstream_SetsScheme(t *testing.T) {
	h := &request.URLRewriter{}
	ctx := &aitm.ProxyContext{
		Phishlet: &aitm.Phishlet{
			ProxyHosts: []aitm.ProxyHost{
				{PhishSubdomain: "login", OrigSubdomain: "login", Domain: "target.local", UpstreamScheme: "http"},
			},
			BaseDomain: "phish.local",
		},
	}
	req := newReq(http.MethodGet, "https://login.phish.local:8443/", nil)
	req.Host = "login.phish.local:8443"

	if err := h.Handle(ctx, req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.URL.Scheme != "http" {
		t.Errorf("expected scheme http for HTTP upstream, got %q", req.URL.Scheme)
	}
}
