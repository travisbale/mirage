package sqlite_test

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/store/sqlite"
)

func TestSessions_RoundTrip(t *testing.T) {
	s := sqlite.NewSessionStore(openTestDB(t))

	session := &aitm.Session{
		ID:         "sess-1",
		Phishlet:   "microsoft",
		RemoteAddr: "203.0.113.5:12345",
		StartedAt:  time.Now().Truncate(time.Second),
		Custom:     map[string]string{"k": "v"},
	}

	if err := s.CreateSession(session); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	got, err := s.GetSession(session.ID)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if got.Phishlet != session.Phishlet {
		t.Errorf("Phishlet: got %q, want %q", got.Phishlet, session.Phishlet)
	}
	if got.Custom["k"] != "v" {
		t.Errorf("Custom map not round-tripped correctly")
	}

	// Update
	got.Username = "alice@corp.com"
	if err := s.UpdateSession(got); err != nil {
		t.Fatalf("UpdateSession: %v", err)
	}
	got2, _ := s.GetSession(session.ID)
	if got2.Username != "alice@corp.com" {
		t.Errorf("Username after update: got %q", got2.Username)
	}

	// Delete
	if err := s.DeleteSession(session.ID); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}
	if _, err := s.GetSession(session.ID); !errors.Is(err, aitm.ErrNotFound) {
		t.Errorf("after delete: got %v, want ErrNotFound", err)
	}
}

func TestSessions_Errors(t *testing.T) {
	s := sqlite.NewSessionStore(openTestDB(t))
	session := &aitm.Session{ID: "s1", Phishlet: "p", StartedAt: time.Now()}
	_ = s.CreateSession(session)

	if err := s.CreateSession(session); !errors.Is(err, aitm.ErrConflict) {
		t.Errorf("duplicate create: got %v, want ErrConflict", err)
	}
	if _, err := s.GetSession("missing"); !errors.Is(err, aitm.ErrNotFound) {
		t.Errorf("missing get: got %v, want ErrNotFound", err)
	}
	if err := s.DeleteSession("missing"); !errors.Is(err, aitm.ErrNotFound) {
		t.Errorf("missing delete: got %v, want ErrNotFound", err)
	}
}

func TestSessions_ListFilter(t *testing.T) {
	s := sqlite.NewSessionStore(openTestDB(t))

	for i, phishlet := range []string{"microsoft", "microsoft", "google"} {
		_ = s.CreateSession(&aitm.Session{
			ID:        fmt.Sprintf("s%d", i),
			Phishlet:  phishlet,
			StartedAt: time.Now(),
		})
	}

	all, _ := s.ListSessions(aitm.SessionFilter{})
	if len(all) != 3 {
		t.Errorf("all: got %d, want 3", len(all))
	}

	ms, _ := s.ListSessions(aitm.SessionFilter{Phishlet: "microsoft"})
	if len(ms) != 2 {
		t.Errorf("microsoft filter: got %d, want 2", len(ms))
	}

	// Complete one session then filter by completed.
	sess, _ := s.GetSession("s0")
	sess.Complete()
	_ = s.UpdateSession(sess)

	done, _ := s.ListSessions(aitm.SessionFilter{CompletedOnly: true})
	if len(done) != 1 {
		t.Errorf("CompletedOnly: got %d, want 1", len(done))
	}

	_, err := s.ListSessions(aitm.SessionFilter{CompletedOnly: true, IncompleteOnly: true})
	if !errors.Is(err, aitm.ErrInvalidFilter) {
		t.Errorf("contradictory filter: got %v, want ErrInvalidFilter", err)
	}
}

func TestSessions_Count(t *testing.T) {
	s := sqlite.NewSessionStore(openTestDB(t))

	for i, phishlet := range []string{"microsoft", "microsoft", "google"} {
		_ = s.CreateSession(&aitm.Session{
			ID:        fmt.Sprintf("s%d", i),
			Phishlet:  phishlet,
			StartedAt: time.Now(),
		})
	}

	total, err := s.CountSessions(aitm.SessionFilter{})
	if err != nil {
		t.Fatalf("CountSessions: %v", err)
	}
	if total != 3 {
		t.Errorf("total: got %d, want 3", total)
	}

	ms, _ := s.CountSessions(aitm.SessionFilter{Phishlet: "microsoft"})
	if ms != 2 {
		t.Errorf("microsoft: got %d, want 2", ms)
	}

	// Complete one session then count incomplete.
	sess, _ := s.GetSession("s0")
	sess.Complete()
	_ = s.UpdateSession(sess)

	incomplete, _ := s.CountSessions(aitm.SessionFilter{IncompleteOnly: true})
	if incomplete != 2 {
		t.Errorf("incomplete: got %d, want 2", incomplete)
	}

	_, err = s.CountSessions(aitm.SessionFilter{CompletedOnly: true, IncompleteOnly: true})
	if !errors.Is(err, aitm.ErrInvalidFilter) {
		t.Errorf("contradictory filter: got %v, want ErrInvalidFilter", err)
	}
}
