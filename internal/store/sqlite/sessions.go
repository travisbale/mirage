package sqlite

import (
	"database/sql"
	"encoding/json"
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

// encryptSensitiveFields encrypts the 7 sensitive session fields for storage as BLOBs.
func (s *Sessions) encryptSensitiveFields(session *aitm.Session, custom, lureParams, cookies, body, httpTok []byte) (
	eUsername, ePassword, eCustom, eLureParams, eCookies, eBody, eHTTPTok []byte, err error,
) {
	fields := []struct {
		name  string
		value []byte
		dest  *[]byte
	}{
		{"username", []byte(session.Username), &eUsername},
		{"password", []byte(session.Password), &ePassword},
		{"custom", custom, &eCustom},
		{"lure_params", lureParams, &eLureParams},
		{"cookie_tokens", cookies, &eCookies},
		{"body_tokens", body, &eBody},
		{"http_tokens", httpTok, &eHTTPTok},
	}
	for _, f := range fields {
		if len(f.value) == 0 {
			continue
		}
		*f.dest, err = s.cipher.Encrypt(f.value)
		if err != nil {
			return nil, nil, nil, nil, nil, nil, nil, fmt.Errorf("encrypting %s for session %s: %w", f.name, session.ID, err)
		}
	}
	return
}

// decryptSensitiveFields decrypts the 7 sensitive session fields read from storage.
func (s *Sessions) decryptSensitiveFields(session *aitm.Session, username, password, custom, lureParams, cookies, body, httpTok []byte) (
	dCustom, dLureParams, dCookies, dBody, dHTTPTok []byte, err error,
) {
	// Decrypt credential strings directly onto the session.
	if len(username) > 0 {
		plain, decErr := s.cipher.Decrypt(username)
		if decErr != nil {
			return nil, nil, nil, nil, nil, fmt.Errorf("decrypting username for session %s: %w", session.ID, decErr)
		}
		session.Username = string(plain)
	}
	if len(password) > 0 {
		plain, decErr := s.cipher.Decrypt(password)
		if decErr != nil {
			return nil, nil, nil, nil, nil, fmt.Errorf("decrypting password for session %s: %w", session.ID, decErr)
		}
		session.Password = string(plain)
	}

	// Decrypt JSON fields.
	fields := []struct {
		name string
		src  []byte
		dest *[]byte
	}{
		{"custom", custom, &dCustom},
		{"lure_params", lureParams, &dLureParams},
		{"cookie_tokens", cookies, &dCookies},
		{"body_tokens", body, &dBody},
		{"http_tokens", httpTok, &dHTTPTok},
	}
	for _, f := range fields {
		if len(f.src) == 0 {
			continue
		}
		*f.dest, err = s.cipher.Decrypt(f.src)
		if err != nil {
			return nil, nil, nil, nil, nil, fmt.Errorf("decrypting %s for session %s: %w", f.name, session.ID, err)
		}
	}
	return
}

func (s *Sessions) CreateSession(session *aitm.Session) error {
	custom, lureParams, cookies, body, httpTok, err := marshalSessionFields(session)
	if err != nil {
		return err
	}

	eUsername, ePassword, eCustom, eLureParams, eCookies, eBody, eHTTPTok, err :=
		s.encryptSensitiveFields(session, custom, lureParams, cookies, body, httpTok)
	if err != nil {
		return err
	}

	var completedAt *int64
	if session.CompletedAt != nil {
		t := session.CompletedAt.Unix()
		completedAt = &t
	}
	_, err = s.db.Exec(`
		INSERT INTO sessions
			(id, phishlet, lure_id, remote_addr, user_agent, ja4_hash,
			 bot_score, username, password, custom, lure_params, cookie_tokens, body_tokens,
			 http_tokens, puppet_id, started_at, completed_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		session.ID, session.Phishlet, session.LureID, session.RemoteAddr, session.UserAgent,
		session.JA4Hash, session.BotScore, eUsername, ePassword,
		eCustom, eLureParams, eCookies, eBody, eHTTPTok, session.PuppetID,
		session.StartedAt.Unix(), completedAt,
	)
	if isConflict(err) {
		return aitm.ErrConflict
	}
	return err
}

func (s *Sessions) GetSession(id string) (*aitm.Session, error) {
	row := s.db.QueryRow(`SELECT
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

	eUsername, ePassword, eCustom, eLureParams, eCookies, eBody, eHTTPTok, err :=
		s.encryptSensitiveFields(session, custom, lureParams, cookies, body, httpTok)
	if err != nil {
		return err
	}

	var completedAt *int64
	if session.CompletedAt != nil {
		t := session.CompletedAt.Unix()
		completedAt = &t
	}
	res, err := s.db.Exec(`
		UPDATE sessions SET
			phishlet=?, lure_id=?, remote_addr=?, user_agent=?, ja4_hash=?,
			bot_score=?, username=?, password=?, custom=?, lure_params=?, cookie_tokens=?,
			body_tokens=?, http_tokens=?, puppet_id=?, started_at=?, completed_at=?
		WHERE id=?`,
		session.Phishlet, session.LureID, session.RemoteAddr, session.UserAgent, session.JA4Hash,
		session.BotScore, eUsername, ePassword,
		eCustom, eLureParams, eCookies, eBody, eHTTPTok, session.PuppetID,
		session.StartedAt.Unix(), completedAt, session.ID,
	)
	if err != nil {
		return err
	}
	return requireOneRow(res)
}

func (s *Sessions) DeleteSession(id string) error {
	res, err := s.db.Exec(`DELETE FROM sessions WHERE id = ?`, id)
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

	rows, err := s.db.Query(q, args...)
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
	if err := s.db.QueryRow(q, args...).Scan(&count); err != nil {
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
		username    []byte
		password    []byte
		custom      []byte
		lureParams  []byte
		cookies     []byte
		body        []byte
		httpTok     []byte
	)
	err := row.Scan(
		&session.ID, &session.Phishlet, &session.LureID, &session.RemoteAddr, &session.UserAgent,
		&session.JA4Hash, &session.BotScore, &username, &password,
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
		s.decryptSensitiveFields(&session, username, password, custom, lureParams, cookies, body, httpTok)
	if err != nil {
		return nil, err
	}

	if err := unmarshalSessionFields(&session, custom, lureParams, cookies, body, httpTok); err != nil {
		return nil, err
	}
	return &session, nil
}

// marshalSessionFields marshals the JSON-serialized fields of a session.
func marshalSessionFields(s *aitm.Session) (custom, lureParams, cookies, body, httpTok []byte, err error) {
	if custom, err = json.Marshal(s.Custom); err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("marshaling custom fields for session %s: %w", s.ID, err)
	}
	if lureParams, err = json.Marshal(s.LureParams); err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("marshaling lure params for session %s: %w", s.ID, err)
	}
	if cookies, err = json.Marshal(s.CookieTokens); err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("marshaling cookie tokens for session %s: %w", s.ID, err)
	}
	if body, err = json.Marshal(s.BodyTokens); err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("marshaling body tokens for session %s: %w", s.ID, err)
	}
	if httpTok, err = json.Marshal(s.HTTPTokens); err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("marshaling http tokens for session %s: %w", s.ID, err)
	}
	return
}

// unmarshalSessionFields populates the JSON-serialized fields of a session.
// Nil slices (from NULL BLOBs) are skipped, leaving the field at its zero value.
func unmarshalSessionFields(s *aitm.Session, custom, lureParams, cookies, body, httpTok []byte) error {
	fields := []struct {
		name string
		src  []byte
		dest any
	}{
		{"custom", custom, &s.Custom},
		{"lure_params", lureParams, &s.LureParams},
		{"cookie_tokens", cookies, &s.CookieTokens},
		{"body_tokens", body, &s.BodyTokens},
		{"http_tokens", httpTok, &s.HTTPTokens},
	}
	for _, f := range fields {
		if len(f.src) == 0 {
			continue
		}
		if err := json.Unmarshal(f.src, f.dest); err != nil {
			return fmt.Errorf("unmarshaling %s for session %s: %w", f.name, s.ID, err)
		}
	}
	return nil
}
