package aitm_test

import (
	"net/http"
	"regexp"
	"testing"
	"time"

	"github.com/travisbale/mirage/internal/aitm"
)

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

// ── Session.AddCookie ───────────────────────────────────────────────────

func TestAddCookie_LazyInit(t *testing.T) {
	session := &aitm.Session{}
	token := &http.Cookie{Name: "auth", Value: "secret", Domain: ".example.com"}

	session.AddCookie(token)

	if session.CookieTokens == nil {
		t.Fatal("expected CookieTokens to be initialized")
	}
	stored := session.CookieTokens[".example.com"]["auth"]
	if stored == nil || stored.Value != "secret" {
		t.Errorf("expected stored token with value 'secret', got %v", stored)
	}
}

func TestAddCookie_MultipleDomains(t *testing.T) {
	session := &aitm.Session{}
	session.AddCookie(&http.Cookie{Name: "tok1", Value: "v1", Domain: ".a.com"})
	session.AddCookie(&http.Cookie{Name: "tok2", Value: "v2", Domain: ".b.com"})

	if len(session.CookieTokens) != 2 {
		t.Errorf("expected 2 domains, got %d", len(session.CookieTokens))
	}
}

// ── Session.ExportCookies ────────────────────────────────────────────────────

func TestExportCookies_ReturnsAllTokens(t *testing.T) {
	session := &aitm.Session{}
	session.AddCookie(&http.Cookie{
		Name: "tok1", Value: "v1", Domain: ".a.com", Path: "/",
		Expires: time.Unix(1700000000, 0),
	})
	session.AddCookie(&http.Cookie{
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
	session.AddCookie(&http.Cookie{
		Name: "authToken", Value: "secret", Domain: "login.microsoft.com",
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

func TestHasRequiredTokens_BodyToken(t *testing.T) {
	session := &aitm.Session{
		BodyTokens: map[string]string{"access_token": "tok123"},
	}
	phishlet := &aitm.Phishlet{
		AuthTokens: []aitm.TokenRule{
			{Type: aitm.TokenTypeBody, Name: regexp.MustCompile(`access_token`)},
		},
	}
	if !session.HasRequiredTokens(phishlet) {
		t.Error("expected true when body token is captured")
	}
}

func TestHasRequiredTokens_MissingBodyToken(t *testing.T) {
	session := &aitm.Session{
		BodyTokens: map[string]string{},
	}
	phishlet := &aitm.Phishlet{
		AuthTokens: []aitm.TokenRule{
			{Type: aitm.TokenTypeBody, Name: regexp.MustCompile(`access_token`)},
		},
	}
	if session.HasRequiredTokens(phishlet) {
		t.Error("expected false when body token is missing")
	}
}

func TestHasRequiredTokens_EmptyValueBodyToken(t *testing.T) {
	session := &aitm.Session{
		BodyTokens: map[string]string{"access_token": ""},
	}
	phishlet := &aitm.Phishlet{
		AuthTokens: []aitm.TokenRule{
			{Type: aitm.TokenTypeBody, Name: regexp.MustCompile(`access_token`)},
		},
	}
	if session.HasRequiredTokens(phishlet) {
		t.Error("expected false when body token has empty value")
	}
}

func TestHasRequiredTokens_MixedTokenTypes(t *testing.T) {
	session := &aitm.Session{
		CookieTokens: map[string]map[string]*http.Cookie{
			"example.com": {"session": {Name: "session", Value: "abc"}},
		},
		BodyTokens: map[string]string{"access_token": "tok456"},
	}
	phishlet := &aitm.Phishlet{
		AuthTokens: []aitm.TokenRule{
			{Type: aitm.TokenTypeCookie, Domain: "example.com", Name: regexp.MustCompile(`^session$`)},
			{Type: aitm.TokenTypeBody, Name: regexp.MustCompile(`access_token`)},
		},
	}
	if !session.HasRequiredTokens(phishlet) {
		t.Error("expected true when both cookie and body tokens are captured")
	}
}

func TestHasRequiredTokens_MixedTokenTypes_OneMissing(t *testing.T) {
	session := &aitm.Session{
		CookieTokens: map[string]map[string]*http.Cookie{
			"example.com": {"session": {Name: "session", Value: "abc"}},
		},
		BodyTokens: map[string]string{},
	}
	phishlet := &aitm.Phishlet{
		AuthTokens: []aitm.TokenRule{
			{Type: aitm.TokenTypeCookie, Domain: "example.com", Name: regexp.MustCompile(`^session$`)},
			{Type: aitm.TokenTypeBody, Name: regexp.MustCompile(`access_token`)},
		},
	}
	if session.HasRequiredTokens(phishlet) {
		t.Error("expected false when body token is missing even though cookie is present")
	}
}
