package aitm_test

import (
	"regexp"
	"testing"
	"time"

	"github.com/travisbale/mirage/internal/aitm"
)

// ── Phishlet.MatchesHost ─────────────────────────────────────────────────────

func TestMatchesHost_Match(t *testing.T) {
	phishlet := &aitm.Phishlet{
		ProxyHosts: []aitm.ProxyHost{
			{PhishSubdomain: "login", Domain: "microsoft.com"},
		},
	}
	if !phishlet.MatchesHost("login.phish.example.com", "phish.example.com") {
		t.Error("expected hostname to match")
	}
}

func TestMatchesHost_NoMatch(t *testing.T) {
	phishlet := &aitm.Phishlet{
		ProxyHosts: []aitm.ProxyHost{
			{PhishSubdomain: "login", Domain: "microsoft.com"},
		},
	}
	if phishlet.MatchesHost("other.phish.example.com", "phish.example.com") {
		t.Error("expected hostname not to match")
	}
}

func TestMatchesHost_MultipleHosts(t *testing.T) {
	phishlet := &aitm.Phishlet{
		ProxyHosts: []aitm.ProxyHost{
			{PhishSubdomain: "login", Domain: "microsoft.com"},
			{PhishSubdomain: "account", Domain: "microsoft.com"},
		},
	}
	if !phishlet.MatchesHost("account.phish.example.com", "phish.example.com") {
		t.Error("expected second proxy host to match")
	}
}

// ── Phishlet.FindLanding ─────────────────────────────────────────────────────

func TestFindLanding_Present(t *testing.T) {
	phishlet := &aitm.Phishlet{
		ProxyHosts: []aitm.ProxyHost{
			{PhishSubdomain: "api", Domain: "microsoft.com", IsLanding: false},
			{PhishSubdomain: "login", Domain: "microsoft.com", IsLanding: true},
		},
	}
	landing := phishlet.FindLanding()
	if landing == nil {
		t.Fatal("expected landing host, got nil")
	}
	if landing.PhishSubdomain != "login" {
		t.Errorf("expected login landing host, got %q", landing.PhishSubdomain)
	}
}

func TestFindLanding_Absent(t *testing.T) {
	phishlet := &aitm.Phishlet{
		ProxyHosts: []aitm.ProxyHost{
			{PhishSubdomain: "api", Domain: "microsoft.com", IsLanding: false},
		},
	}
	if phishlet.FindLanding() != nil {
		t.Error("expected nil when no landing host exists")
	}
}

// ── Phishlet.MatchesAuthURL ──────────────────────────────────────────────────

func TestMatchesAuthURL_Match(t *testing.T) {
	phishlet := &aitm.Phishlet{
		AuthURLs: []*regexp.Regexp{
			regexp.MustCompile(`/authorize\?`),
		},
	}
	if !phishlet.MatchesAuthURL("https://login.example.com/authorize?client_id=abc") {
		t.Error("expected auth URL to match")
	}
}

func TestMatchesAuthURL_NoMatch(t *testing.T) {
	phishlet := &aitm.Phishlet{
		AuthURLs: []*regexp.Regexp{
			regexp.MustCompile(`/authorize\?`),
		},
	}
	if phishlet.MatchesAuthURL("https://login.example.com/logout") {
		t.Error("expected auth URL not to match")
	}
}

func TestMatchesAuthURL_MultiplePatterns(t *testing.T) {
	phishlet := &aitm.Phishlet{
		AuthURLs: []*regexp.Regexp{
			regexp.MustCompile(`/authorize\?`),
			regexp.MustCompile(`/oauth2/token`),
		},
	}
	if !phishlet.MatchesAuthURL("https://login.example.com/oauth2/token") {
		t.Error("expected second pattern to match")
	}
}

// ── ProxyHost.OriginHost ─────────────────────────────────────────────────────

func TestOriginHost_WithSubdomain(t *testing.T) {
	host := aitm.ProxyHost{OrigSubdomain: "login", Domain: "microsoftonline.com"}
	if got := host.OriginHost(); got != "login.microsoftonline.com" {
		t.Errorf("got %q, want %q", got, "login.microsoftonline.com")
	}
}

func TestOriginHost_WithoutSubdomain(t *testing.T) {
	host := aitm.ProxyHost{Domain: "example.com"}
	if got := host.OriginHost(); got != "example.com" {
		t.Errorf("got %q, want %q", got, "example.com")
	}
}

// ── Session.IsDone / HasCredentials ──────────────────────────────────────────

func TestIsDone_Completed(t *testing.T) {
	now := time.Now()
	session := &aitm.Session{CompletedAt: &now}
	if !session.IsDone() {
		t.Error("expected IsDone=true when CompletedAt is set")
	}
}

func TestIsDone_NotCompleted(t *testing.T) {
	session := &aitm.Session{}
	if session.IsDone() {
		t.Error("expected IsDone=false when CompletedAt is nil")
	}
}

func TestHasCredentials_WithUsername(t *testing.T) {
	session := &aitm.Session{Username: "victim@example.com"}
	if !session.HasCredentials() {
		t.Error("expected HasCredentials=true")
	}
}

func TestHasCredentials_Empty(t *testing.T) {
	session := &aitm.Session{}
	if session.HasCredentials() {
		t.Error("expected HasCredentials=false")
	}
}

// ── Session.AddCookieToken ───────────────────────────────────────────────────

func TestAddCookieToken_LazyInit(t *testing.T) {
	session := &aitm.Session{}
	token := &aitm.CookieToken{Name: "auth", Value: "secret", Domain: ".example.com"}

	session.AddCookieToken(".example.com", "auth", token)

	if session.CookieTokens == nil {
		t.Fatal("expected CookieTokens to be initialized")
	}
	stored := session.CookieTokens[".example.com"]["auth"]
	if stored == nil || stored.Value != "secret" {
		t.Errorf("expected stored token with value 'secret', got %v", stored)
	}
}

func TestAddCookieToken_MultipleDomains(t *testing.T) {
	session := &aitm.Session{}
	session.AddCookieToken(".a.com", "tok1", &aitm.CookieToken{Name: "tok1", Value: "v1"})
	session.AddCookieToken(".b.com", "tok2", &aitm.CookieToken{Name: "tok2", Value: "v2"})

	if len(session.CookieTokens) != 2 {
		t.Errorf("expected 2 domains, got %d", len(session.CookieTokens))
	}
}

// ── Session.ExportCookies ────────────────────────────────────────────────────

func TestExportCookies_ReturnsAllTokens(t *testing.T) {
	session := &aitm.Session{}
	session.AddCookieToken(".a.com", "tok1", &aitm.CookieToken{
		Name: "tok1", Value: "v1", Domain: ".a.com", Path: "/",
		Expires: time.Unix(1700000000, 0),
	})
	session.AddCookieToken(".b.com", "tok2", &aitm.CookieToken{
		Name: "tok2", Value: "v2", Domain: ".b.com", Path: "/app",
		HttpOnly: true, Secure: true,
	})

	exported := session.ExportCookies()
	if len(exported) != 2 {
		t.Fatalf("expected 2 exported cookies, got %d", len(exported))
	}

	found := map[string]bool{}
	for _, cookie := range exported {
		found[cookie.Name] = true
	}
	if !found["tok1"] || !found["tok2"] {
		t.Errorf("expected both cookies exported, got %v", exported)
	}
}

// ── Session.HasRequiredTokens ────────────────────────────────────────────────

func TestHasRequiredTokens_NilPhishlet(t *testing.T) {
	session := &aitm.Session{}
	if session.HasRequiredTokens(nil) {
		t.Error("expected false when phishlet is nil")
	}
}

func TestHasRequiredTokens_AllCaptured(t *testing.T) {
	session := &aitm.Session{}
	session.AddCookieToken("login.microsoft.com", "authToken", &aitm.CookieToken{
		Name: "authToken", Value: "secret",
	})

	phishlet := &aitm.Phishlet{
		AuthTokens: []aitm.TokenRule{
			{Type: aitm.TokenTypeCookie, Domain: "microsoft.com", Name: regexp.MustCompile(`^authToken$`)},
		},
	}
	if !session.HasRequiredTokens(phishlet) {
		t.Error("expected true when all required tokens are captured")
	}
}

func TestHasRequiredTokens_MissingToken(t *testing.T) {
	session := &aitm.Session{}

	phishlet := &aitm.Phishlet{
		AuthTokens: []aitm.TokenRule{
			{Type: aitm.TokenTypeCookie, Domain: "microsoft.com", Name: regexp.MustCompile(`^authToken$`)},
		},
	}
	if session.HasRequiredTokens(phishlet) {
		t.Error("expected false when required token is missing")
	}
}

func TestHasRequiredTokens_SkipsAlwaysTokens(t *testing.T) {
	session := &aitm.Session{} // no tokens captured at all

	phishlet := &aitm.Phishlet{
		AuthTokens: []aitm.TokenRule{
			{Type: aitm.TokenTypeCookie, Domain: "microsoft.com", Name: regexp.MustCompile(`^optional$`), Always: true},
		},
	}
	if !session.HasRequiredTokens(phishlet) {
		t.Error("expected true when only always-tokens are defined")
	}
}

func TestHasRequiredTokens_HTTPHeaderToken(t *testing.T) {
	session := &aitm.Session{
		HTTPTokens: map[string]string{"Authorization": "Bearer xyz"},
	}

	phishlet := &aitm.Phishlet{
		AuthTokens: []aitm.TokenRule{
			{Type: aitm.TokenTypeHTTPHeader, Name: regexp.MustCompile(`^Authorization$`)},
		},
	}
	if !session.HasRequiredTokens(phishlet) {
		t.Error("expected true when HTTP header token is captured")
	}
}

func TestHasRequiredTokens_MissingHTTPHeaderToken(t *testing.T) {
	session := &aitm.Session{
		HTTPTokens: map[string]string{},
	}

	phishlet := &aitm.Phishlet{
		AuthTokens: []aitm.TokenRule{
			{Type: aitm.TokenTypeHTTPHeader, Name: regexp.MustCompile(`^Authorization$`)},
		},
	}
	if session.HasRequiredTokens(phishlet) {
		t.Error("expected false when HTTP header token is missing")
	}
}

func TestHasRequiredTokens_EmptyValueHTTPHeaderToken(t *testing.T) {
	session := &aitm.Session{
		HTTPTokens: map[string]string{"Authorization": ""},
	}

	phishlet := &aitm.Phishlet{
		AuthTokens: []aitm.TokenRule{
			{Type: aitm.TokenTypeHTTPHeader, Name: regexp.MustCompile(`^Authorization$`)},
		},
	}
	if session.HasRequiredTokens(phishlet) {
		t.Error("expected false when HTTP header token has empty value")
	}
}

// ── SubFilter.MatchesMIME ────────────────────────────────────────────────────

func TestMatchesMIME_Match(t *testing.T) {
	filter := aitm.SubFilter{MimeTypes: []string{"text/html", "application/json"}}
	if !filter.MatchesMIME("text/html; charset=utf-8") {
		t.Error("expected text/html to match with prefix")
	}
}

func TestMatchesMIME_NoMatch(t *testing.T) {
	filter := aitm.SubFilter{MimeTypes: []string{"text/html"}}
	if filter.MatchesMIME("application/json") {
		t.Error("expected application/json not to match text/html filter")
	}
}
