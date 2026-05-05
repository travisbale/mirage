package aitm_test

import (
	"errors"
	"net/http"
	"regexp"
	"testing"
	"time"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/sdk"
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

type stubSessionStore struct {
	sessions map[string]*aitm.Session
	err      error
}

func newStubSessionStore() *stubSessionStore {
	return &stubSessionStore{sessions: make(map[string]*aitm.Session)}
}

func (s *stubSessionStore) CreateSession(sess *aitm.Session) error {
	if s.err != nil {
		return s.err
	}
	s.sessions[sess.ID] = sess
	return nil
}

func (s *stubSessionStore) GetSession(id string) (*aitm.Session, error) {
	if s.err != nil {
		return nil, s.err
	}
	sess, ok := s.sessions[id]
	if !ok {
		return nil, errors.New("not found")
	}
	return sess, nil
}

func (s *stubSessionStore) UpdateSession(sess *aitm.Session) error {
	if s.err != nil {
		return s.err
	}
	s.sessions[sess.ID] = sess
	return nil
}

func (s *stubSessionStore) DeleteSession(id string) error {
	delete(s.sessions, id)
	return s.err
}

func (s *stubSessionStore) ListSessions(_ aitm.SessionFilter) ([]*aitm.Session, error) {
	var out []*aitm.Session
	for _, sess := range s.sessions {
		out = append(out, sess)
	}
	return out, s.err
}

func (s *stubSessionStore) CountSessions(_ aitm.SessionFilter) (int, error) {
	return len(s.sessions), s.err
}

func newSessionService() (*aitm.SessionService, *stubSessionStore, *stubBus) {
	store := newStubSessionStore()
	bus := &stubBus{}
	svc := &aitm.SessionService{Store: store, Bus: bus}
	return svc, store, bus
}

func TestSessionService_NewSession_CachesAndPersists(t *testing.T) {
	svc, store, bus := newSessionService()
	sess, err := svc.NewSession("1.2.3.4", "", "Mozilla/5.0", "lure-1", "test", nil)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	if sess.ID == "" {
		t.Fatal("expected non-empty session ID")
	}
	if sess.RemoteAddr != "1.2.3.4" {
		t.Errorf("RemoteAddr = %q, want %q", sess.RemoteAddr, "1.2.3.4")
	}

	// Should be in store
	if _, ok := store.sessions[sess.ID]; !ok {
		t.Error("expected session persisted to store")
	}

	// Should be in cache (Get returns without hitting store)
	store.err = errors.New("store should not be called")
	got, err := svc.Get(sess.ID)
	if err != nil {
		t.Fatalf("Get from cache: %v", err)
	}
	if got != sess {
		t.Error("expected Get to return cached session")
	}
	store.err = nil

	// Should publish EventSessionCreated
	if len(bus.published) != 1 || bus.published[0].Type != sdk.EventSessionCreated {
		t.Errorf("expected EventSessionCreated, got %v", bus.published)
	}
}

func TestSessionService_Get_FallsBackToStore(t *testing.T) {
	svc, store, _ := newSessionService()

	// Insert directly into store (bypassing cache)
	stored := &aitm.Session{ID: "stored-only"}
	store.sessions["stored-only"] = stored

	got, err := svc.Get("stored-only")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != stored {
		t.Error("expected Get to fall back to store")
	}
}

func TestSessionService_Get_NotFound(t *testing.T) {
	svc, _, _ := newSessionService()

	_, err := svc.Get("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent session")
	}
}

func TestSessionService_Complete_EvictsFromCache(t *testing.T) {
	svc, store, bus := newSessionService()
	sess, _ := svc.NewSession("1.2.3.4", "", "Mozilla/5.0", "lure-1", "test", nil)

	if err := svc.Complete(sess); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if sess.CompletedAt == nil {
		t.Error("expected CompletedAt to be set")
	}

	// Should be evicted from cache — Get now hits store
	got, err := svc.Get(sess.ID)
	if err != nil {
		t.Fatalf("Get after complete: %v", err)
	}
	if got != store.sessions[sess.ID] {
		t.Error("expected Get to return from store after cache eviction")
	}

	// Should publish EventSessionCompleted (second event after EventSessionCreated)
	if len(bus.published) != 2 || bus.published[1].Type != sdk.EventSessionCompleted {
		t.Errorf("expected EventSessionCompleted, got %v", bus.published)
	}
}

func TestSessionService_CaptureCredentials_PersistsAndPublishes(t *testing.T) {
	svc, store, bus := newSessionService()
	sess, _ := svc.NewSession("1.2.3.4", "", "Mozilla/5.0", "lure-1", "test", nil)
	sess.Username = "victim@example.com"
	sess.Password = "hunter2"

	if err := svc.CaptureCredentials(sess); err != nil {
		t.Fatalf("CaptureCredentials: %v", err)
	}

	// Credentials should be persisted
	stored := store.sessions[sess.ID]
	if stored.Username != "victim@example.com" {
		t.Errorf("stored username = %q, want %q", stored.Username, "victim@example.com")
	}

	// Should publish EventCredsCaptured
	if len(bus.published) != 2 || bus.published[1].Type != sdk.EventCredsCaptured {
		t.Errorf("expected EventCredsCaptured, got %v", bus.published)
	}
}

func TestSessionService_Update_PersistsWithoutEvent(t *testing.T) {
	svc, store, bus := newSessionService()
	sess, _ := svc.NewSession("1.2.3.4", "", "Mozilla/5.0", "lure-1", "test", nil)
	sess.Custom = map[string]string{"campaign": "test"}

	if err := svc.Update(sess); err != nil {
		t.Fatalf("Update: %v", err)
	}

	stored := store.sessions[sess.ID]
	if stored.Custom["campaign"] != "test" {
		t.Errorf("stored custom = %q, want %q", stored.Custom["campaign"], "test")
	}

	// Update should not publish any event (only EventSessionCreated from NewSession).
	if len(bus.published) != 1 {
		t.Errorf("expected 1 event (session created only), got %d", len(bus.published))
	}
}

func TestSessionService_CaptureTokens_PersistsAndPublishes(t *testing.T) {
	svc, store, bus := newSessionService()
	sess, _ := svc.NewSession("1.2.3.4", "", "Mozilla/5.0", "lure-1", "test", nil)
	sess.HTTPTokens = map[string]string{"X-Auth": "bearer-abc"}

	if err := svc.CaptureTokens(sess); err != nil {
		t.Fatalf("CaptureTokens: %v", err)
	}

	stored := store.sessions[sess.ID]
	if stored.HTTPTokens["X-Auth"] != "bearer-abc" {
		t.Errorf("stored HTTP token = %q, want %q", stored.HTTPTokens["X-Auth"], "bearer-abc")
	}

	// Should publish EventTokensCaptured (index 1, after EventSessionCreated from NewSession)
	if len(bus.published) != 2 || bus.published[1].Type != sdk.EventTokensCaptured {
		types := make([]sdk.EventType, len(bus.published))
		for i, e := range bus.published {
			types[i] = e.Type
		}
		t.Errorf("expected [EventSessionCreated, EventTokensCaptured], got %v", types)
	}
}

func TestSessionService_Delete_EvictsFromCacheAndStore(t *testing.T) {
	svc, store, _ := newSessionService()
	sess, _ := svc.NewSession("1.2.3.4", "", "Mozilla/5.0", "lure-1", "test", nil)

	if err := svc.Delete(sess.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	// Should be gone from store
	if _, ok := store.sessions[sess.ID]; ok {
		t.Error("expected session deleted from store")
	}

	// Should be gone from cache
	_, err := svc.Get(sess.ID)
	if err == nil {
		t.Error("expected error getting deleted session")
	}
}
