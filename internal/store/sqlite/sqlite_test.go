package sqlite_test

import (
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/store"
	"github.com/travisbale/mirage/internal/store/sqlite"
)

func openTestDB(t *testing.T) *sqlite.DB {
	t.Helper()
	db, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatalf("sqlite.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// --- Sessions ---

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
	if _, err := s.GetSession(session.ID); err != store.ErrNotFound {
		t.Errorf("after delete: got %v, want ErrNotFound", err)
	}
}

func TestSessions_Errors(t *testing.T) {
	s := sqlite.NewSessionStore(openTestDB(t))
	session := &aitm.Session{ID: "s1", Phishlet: "p", StartedAt: time.Now()}
	_ = s.CreateSession(session)

	if err := s.CreateSession(session); err != store.ErrConflict {
		t.Errorf("duplicate create: got %v, want ErrConflict", err)
	}
	if _, err := s.GetSession("missing"); err != store.ErrNotFound {
		t.Errorf("missing get: got %v, want ErrNotFound", err)
	}
	if err := s.DeleteSession("missing"); err != store.ErrNotFound {
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
	if err != store.ErrInvalidFilter {
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
	if err != store.ErrInvalidFilter {
		t.Errorf("contradictory filter: got %v, want ErrInvalidFilter", err)
	}
}

// --- Lures ---

func TestLures_RoundTrip(t *testing.T) {
	s := sqlite.NewLureStore(openTestDB(t))

	l := &aitm.Lure{
		ID:          "lure-1",
		Phishlet:    "microsoft",
		Path:        "/",
		RedirectURL: "https://microsoft.com",
		ParamsKey:   make([]byte, 32),
	}

	if err := s.CreateLure(l); err != nil {
		t.Fatalf("CreateLure: %v", err)
	}
	got, err := s.GetLure(l.ID)
	if err != nil {
		t.Fatalf("GetLure: %v", err)
	}
	if got.RedirectURL != l.RedirectURL {
		t.Errorf("RedirectURL: got %q, want %q", got.RedirectURL, l.RedirectURL)
	}

	got.SpoofURL = "https://spoof.com"
	if err := s.UpdateLure(got); err != nil {
		t.Fatalf("UpdateLure: %v", err)
	}

	list, _ := s.ListLures()
	if len(list) != 1 {
		t.Errorf("ListLures: got %d, want 1", len(list))
	}

	if err := s.DeleteLure(l.ID); err != nil {
		t.Fatalf("DeleteLure: %v", err)
	}
	if _, err := s.GetLure(l.ID); err != store.ErrNotFound {
		t.Errorf("after delete: got %v, want ErrNotFound", err)
	}
}

// --- Phishlets ---

func TestPhishlets_ConfigUpsert(t *testing.T) {
	s := sqlite.NewPhishletStore(openTestDB(t))

	cfg := &aitm.PhishletConfig{
		Name:       "microsoft",
		BaseDomain: "phish.example.com",
		Enabled:    true,
	}

	if err := s.SetPhishletConfig(cfg); err != nil {
		t.Fatalf("SetPhishletConfig: %v", err)
	}
	got, err := s.GetPhishletConfig("microsoft")
	if err != nil {
		t.Fatalf("GetPhishletConfig: %v", err)
	}
	if !got.Enabled {
		t.Error("Enabled should be true")
	}

	// Upsert
	cfg.Enabled = false
	_ = s.SetPhishletConfig(cfg)
	got, _ = s.GetPhishletConfig("microsoft")
	if got.Enabled {
		t.Error("Enabled should be false after upsert")
	}

	if _, err := s.GetPhishletConfig("missing"); err != store.ErrNotFound {
		t.Errorf("missing: got %v, want ErrNotFound", err)
	}
}

func TestPhishlets_SubPhishlets(t *testing.T) {
	s := sqlite.NewPhishletStore(openTestDB(t))

	sp := &aitm.SubPhishlet{
		Name:       "ms-corp",
		ParentName: "microsoft",
		Params:     map[string]string{"tenant": "corp.onmicrosoft.com"},
	}

	if err := s.CreateSubPhishlet(sp); err != nil {
		t.Fatalf("CreateSubPhishlet: %v", err)
	}
	got, err := s.GetSubPhishlet("ms-corp")
	if err != nil {
		t.Fatalf("GetSubPhishlet: %v", err)
	}
	if got.Params["tenant"] != "corp.onmicrosoft.com" {
		t.Errorf("params not round-tripped: got %v", got.Params)
	}

	list, _ := s.ListSubPhishlets("microsoft")
	if len(list) != 1 {
		t.Errorf("ListSubPhishlets: got %d, want 1", len(list))
	}

	if err := s.CreateSubPhishlet(sp); err != store.ErrConflict {
		t.Errorf("duplicate: got %v, want ErrConflict", err)
	}
}

// --- Bots ---

func TestBots_RoundTrip(t *testing.T) {
	db := openTestDB(t)
	// Bot telemetry has a FK to sessions, so create a session first.
	session := &aitm.Session{ID: "sess-bot", Phishlet: "p", StartedAt: time.Now()}
	_ = sqlite.NewSessionStore(db).CreateSession(session)

	s := sqlite.NewBotStore(db)
	tel := &aitm.BotTelemetry{
		ID:          "tel-1",
		SessionID:   "sess-bot",
		CollectedAt: time.Now().Truncate(time.Second),
		Raw:         map[string]any{"ja4": "abc123"},
	}

	if err := s.StoreBotTelemetry(tel); err != nil {
		t.Fatalf("StoreBotTelemetry: %v", err)
	}

	got, err := s.GetBotTelemetry("sess-bot")
	if err != nil {
		t.Fatalf("GetBotTelemetry: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d telemetry records, want 1", len(got))
	}
	if got[0].Raw["ja4"] != "abc123" {
		t.Errorf("Raw not round-tripped: got %v", got[0].Raw)
	}

	if err := s.DeleteBotTelemetry("sess-bot"); err != nil {
		t.Fatalf("DeleteBotTelemetry: %v", err)
	}
	got, _ = s.GetBotTelemetry("sess-bot")
	if len(got) != 0 {
		t.Errorf("after delete: got %d records, want 0", len(got))
	}
}

// --- WithTx ---

func TestWithTx_Rollback(t *testing.T) {
	db := openTestDB(t)

	// A failed transaction should not persist any work.
	err := db.WithTx(func(tx *sql.Tx) error {
		_, _ = tx.Exec(`INSERT INTO sessions (id, phishlet, started_at) VALUES (?,?,?)`, "tx-sess", "p", time.Now().Unix())
		return fmt.Errorf("intentional failure")
	})
	if err == nil {
		t.Fatal("expected error from WithTx, got nil")
	}

	// The session should not exist because the transaction was rolled back.
	s := sqlite.NewSessionStore(db)
	if _, err := s.GetSession("tx-sess"); err != store.ErrNotFound {
		t.Errorf("rolled-back session should not exist, got %v", err)
	}
}
