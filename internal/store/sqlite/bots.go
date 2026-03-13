package sqlite

import (
	"time"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/store"
)

// Compile-time check: Bots satisfies aitm.BotStore.
var _ aitm.BotStore = (*Bots)(nil)

// Bots implements aitm.BotStore backed by SQLite.
type Bots struct{ db *DB }

func NewBots(db *DB) *Bots { return &Bots{db: db} }

func (s *Bots) StoreBotTelemetry(t *aitm.BotTelemetry) error {
	raw, err := marshalJSON(t.Raw)
	if err != nil {
		return err
	}
	_, err = s.db.db.Exec(`
		INSERT INTO bot_telemetry (id, session_id, collected_at, raw)
		VALUES (?,?,?,?)`,
		t.ID, t.SessionID, t.CollectedAt.Unix(), raw,
	)
	if isConflict(err) {
		return store.ErrConflict
	}
	return err
}

func (s *Bots) GetBotTelemetry(sessionID string) ([]*aitm.BotTelemetry, error) {
	rows, err := s.db.db.Query(`
		SELECT id, session_id, collected_at, raw
		FROM bot_telemetry WHERE session_id = ? ORDER BY collected_at ASC`,
		sessionID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*aitm.BotTelemetry
	for rows.Next() {
		var (
			t           aitm.BotTelemetry
			collectedAt int64
			raw         string
		)
		if err := rows.Scan(&t.ID, &t.SessionID, &collectedAt, &raw); err != nil {
			return nil, err
		}
		t.CollectedAt = time.Unix(collectedAt, 0)
		_ = unmarshalJSON(raw, &t.Raw)
		out = append(out, &t)
	}
	return out, rows.Err()
}

func (s *Bots) DeleteBotTelemetry(sessionID string) error {
	_, err := s.db.db.Exec(`DELETE FROM bot_telemetry WHERE session_id = ?`, sessionID)
	return err
}
