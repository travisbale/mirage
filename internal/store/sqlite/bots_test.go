package sqlite_test

import (
	"testing"
	"time"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/store/sqlite"
)

func TestBots_RoundTrip(t *testing.T) {
	db := openTestDB(t)
	// Bot telemetry has a FK to sessions, so create a session first.
	session := &aitm.Session{ID: "sess-bot", Phishlet: "p", StartedAt: time.Now()}
	_ = sqlite.NewSessionStore(db, testCipher()).CreateSession(session)

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
