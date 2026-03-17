package response_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/proxy/handlers/response"
)

func TestCookieRewriter_RewritesDomain(t *testing.T) {
	h := &response.CookieRewriter{}
	resp := newResp(http.StatusOK, "text/html", "")
	resp.Header.Set("Set-Cookie", "session=abc123; Domain=login.microsoft.com; Path=/; Secure")

	ctx := &aitm.ProxyContext{
		Phishlet: &aitm.Phishlet{
			ProxyHosts: []aitm.ProxyHost{
				{PhishSubdomain: "login", OrigSubdomain: "login", Domain: "microsoft.com"},
			},
			BaseDomain: "phish.example.com",
		},
	}

	if err := h.Handle(ctx, resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	setCookie := resp.Header.Get("Set-Cookie")
	if !strings.Contains(setCookie, "phish.example.com") {
		t.Errorf("expected cookie domain rewritten to phish.example.com, got: %s", setCookie)
	}
}

func TestCookieRewriter_RewritesDomainAndForcesSecure(t *testing.T) {
	h := &response.CookieRewriter{}
	resp := newResp(http.StatusOK, "text/html", "")
	resp.Header.Set("Set-Cookie", "session=abc; Domain=login.microsoft.com; Path=/")

	ctx := &aitm.ProxyContext{
		Phishlet: &aitm.Phishlet{
			ProxyHosts: []aitm.ProxyHost{
				{PhishSubdomain: "login", OrigSubdomain: "login", Domain: "microsoft.com"},
			},
			BaseDomain: "phish.example.com",
		},
	}

	if err := h.Handle(ctx, resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	setCookie := resp.Header.Get("Set-Cookie")
	if !strings.Contains(setCookie, "phish.example.com") {
		t.Errorf("expected domain rewritten to phish.example.com, got: %s", setCookie)
	}
	if !strings.Contains(setCookie, "Secure") {
		t.Errorf("expected Secure attribute, got: %s", setCookie)
	}
}

func TestCookieRewriter_NoDomain_PassesThrough(t *testing.T) {
	h := &response.CookieRewriter{}
	resp := newResp(http.StatusOK, "text/html", "")
	resp.Header.Set("Set-Cookie", "tok=xyz; Path=/; HttpOnly")

	ctx := &aitm.ProxyContext{
		Phishlet: &aitm.Phishlet{BaseDomain: "phish.example.com"},
	}

	if err := h.Handle(ctx, resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	setCookie := resp.Header.Get("Set-Cookie")
	if !strings.Contains(setCookie, "tok=xyz") {
		t.Errorf("expected original cookie value preserved, got: %s", setCookie)
	}
}

func TestCookieRewriter_InjectsSessionCookieOnNewSession(t *testing.T) {
	h := &response.CookieRewriter{}
	resp := newResp(http.StatusOK, "text/html", "")

	ctx := &aitm.ProxyContext{
		IsNewSession: true,
		Session:      &aitm.Session{ID: "sess-abc"},
	}

	if err := h.Handle(ctx, resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, v := range resp.Header.Values("Set-Cookie") {
		if strings.Contains(v, "__ss=sess-abc") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected __ss session cookie to be injected, headers: %v", resp.Header["Set-Cookie"])
	}
}
