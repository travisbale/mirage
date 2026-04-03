package aitm_test

import (
	"errors"
	"testing"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/sdk"
)

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
	sess, err := svc.NewSession("1.2.3.4", "", "Mozilla/5.0", "lure-1", "test")
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
	sess, _ := svc.NewSession("1.2.3.4", "", "Mozilla/5.0", "lure-1", "test")

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
	sess, _ := svc.NewSession("1.2.3.4", "", "Mozilla/5.0", "lure-1", "test")
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

func TestSessionService_Update_PersistsAndPublishesTokensCaptured(t *testing.T) {
	svc, store, bus := newSessionService()
	sess, _ := svc.NewSession("1.2.3.4", "", "Mozilla/5.0", "lure-1", "test")
	sess.HTTPTokens = map[string]string{"X-Auth": "bearer-abc"}

	if err := svc.Update(sess); err != nil {
		t.Fatalf("Update: %v", err)
	}

	// Tokens should be persisted
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
	sess, _ := svc.NewSession("1.2.3.4", "", "Mozilla/5.0", "lure-1", "test")

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
