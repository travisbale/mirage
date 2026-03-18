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

type stubHostnameChecker struct{ hosts map[string]bool }

func (s *stubHostnameChecker) Contains(hostname string) bool { return s.hosts[hostname] }

type stubPhishletResolver struct {
	phishlet *aitm.Phishlet
	lure     *aitm.Lure
	err      error
}

func (s *stubPhishletResolver) ResolveHostname(_, _ string) (*aitm.Phishlet, *aitm.Lure, error) {
	return s.phishlet, s.lure, s.err
}

func TestPhishletRouter_KnownHost_ResolvesPhishlet(t *testing.T) {
	phishlet := &aitm.Phishlet{Name: "microsoft"}
	lure := &aitm.Lure{ID: "lure-1"}
	h := &request.PhishletRouter{
		Hostnames: &stubHostnameChecker{hosts: map[string]bool{"login.phish.example.com": true}},
		Resolver:  &stubPhishletResolver{phishlet: phishlet, lure: lure},
		Spoof:     &stubSpoofer{},
	}
	ctx := &aitm.ProxyContext{}
	req := newReq(http.MethodGet, "https://login.phish.example.com/oauth", nil)
	req.Host = "login.phish.example.com"

	if err := h.Handle(ctx, req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ctx.Phishlet != phishlet {
		t.Error("expected phishlet to be set on context")
	}
	if ctx.Lure != lure {
		t.Error("expected lure to be set on context")
	}
}

func TestPhishletRouter_UnknownHost_Spoofs(t *testing.T) {
	spoofer := &stubSpoofer{}
	h := &request.PhishletRouter{
		Hostnames: &stubHostnameChecker{hosts: map[string]bool{}},
		Resolver:  &stubPhishletResolver{},
		Spoof:     spoofer,
	}
	ctx := &aitm.ProxyContext{ResponseWriter: httptest.NewRecorder()}
	req := newReq(http.MethodGet, "https://unknown.example.com/", nil)
	req.Host = "unknown.example.com"

	err := h.Handle(ctx, req)
	if !errors.Is(err, proxy.ErrShortCircuit) {
		t.Fatalf("expected ErrShortCircuit, got %v", err)
	}
	if !spoofer.called {
		t.Error("expected spoofer to be called for unknown host")
	}
}

func TestPhishletRouter_HostWithPort_StripsPort(t *testing.T) {
	phishlet := &aitm.Phishlet{Name: "microsoft"}
	h := &request.PhishletRouter{
		Hostnames: &stubHostnameChecker{hosts: map[string]bool{"login.phish.example.com": true}},
		Resolver:  &stubPhishletResolver{phishlet: phishlet},
		Spoof:     &stubSpoofer{},
	}
	ctx := &aitm.ProxyContext{}
	req := newReq(http.MethodGet, "https://login.phish.example.com:8443/oauth", nil)
	req.Host = "login.phish.example.com:8443"

	if err := h.Handle(ctx, req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ctx.Phishlet != phishlet {
		t.Error("expected phishlet to be set on context when host includes port")
	}
}

func TestPhishletRouter_ResolverError_ReturnsError(t *testing.T) {
	h := &request.PhishletRouter{
		Hostnames: &stubHostnameChecker{hosts: map[string]bool{"login.example.com": true}},
		Resolver:  &stubPhishletResolver{err: errors.New("not found")},
		Spoof:     &stubSpoofer{},
	}
	ctx := &aitm.ProxyContext{}
	req := newReq(http.MethodGet, "https://login.example.com/", nil)
	req.Host = "login.example.com"

	if err := h.Handle(ctx, req); err == nil {
		t.Fatal("expected error from resolver failure")
	}
}
