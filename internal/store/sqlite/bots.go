package sqlite

import (
	"database/sql"
	"errors"
	"time"

	"github.com/travisbale/mirage/internal/aitm"
	
)

// Bots implements bot telemetry and signature persistence backed by SQLite.
type Bots struct{ db *DB }

func NewBotStore(db *DB) *Bots { return &Bots{db: db} }

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
		return aitm.ErrConflict
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

func (s *Bots) CreateBotSignature(sig aitm.BotSignature) error {
	_, err := s.db.db.Exec(`
		INSERT INTO bot_signatures (ja4_hash, description, added_at)
		VALUES (?,?,?)`,
		sig.JA4Hash, sig.Description, sig.AddedAt.Unix(),
	)
	if isConflict(err) {
		return aitm.ErrConflict
	}
	return err
}

func (s *Bots) LookupBotSignature(ja4Hash string) (aitm.BotSignature, error) {
	row := s.db.db.QueryRow(`SELECT ja4_hash, description, added_at FROM bot_signatures WHERE ja4_hash = ?`, ja4Hash)
	sig, err := scanBotSignature(row)
	if errors.Is(err, sql.ErrNoRows) {
		return aitm.BotSignature{}, aitm.ErrNotFound
	}
	return sig, err
}

func (s *Bots) DeleteBotSignature(ja4Hash string) (bool, error) {
	res, err := s.db.db.Exec(`DELETE FROM bot_signatures WHERE ja4_hash = ?`, ja4Hash)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

func (s *Bots) ListBotSignatures() ([]aitm.BotSignature, error) {
	rows, err := s.db.db.Query(`SELECT ja4_hash, description, added_at FROM bot_signatures ORDER BY added_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []aitm.BotSignature
	for rows.Next() {
		sig, err := scanBotSignature(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sig)
	}
	return out, rows.Err()
}

func scanBotSignature(row scanner) (aitm.BotSignature, error) {
	var sig aitm.BotSignature
	var addedAt int64
	if err := row.Scan(&sig.JA4Hash, &sig.Description, &addedAt); err != nil {
		return aitm.BotSignature{}, err
	}
	sig.AddedAt = time.Unix(addedAt, 0)
	return sig, nil
}
