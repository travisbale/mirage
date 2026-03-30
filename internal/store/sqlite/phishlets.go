package sqlite

import (
	"database/sql"
	"errors"
	"strings"

	"github.com/travisbale/mirage/internal/aitm"
)

// Phishlets implements the phishletStore interface defined in the aitm package.
type Phishlets struct{ db *DB }

func NewPhishletStore(db *DB) *Phishlets { return &Phishlets{db: db} }

func (s *Phishlets) SavePhishlet(name string, yaml string) error {
	_, err := s.db.db.Exec(`
		INSERT INTO phishlets (name, yaml) VALUES (?,?)
		ON CONFLICT(name) DO UPDATE SET yaml=excluded.yaml`,
		name, yaml,
	)
	return err
}

func (s *Phishlets) GetPhishlet(name string) (string, error) {
	var yaml string
	err := s.db.db.QueryRow(`SELECT yaml FROM phishlets WHERE name = ?`, name).Scan(&yaml)
	if errors.Is(err, sql.ErrNoRows) {
		return "", aitm.ErrNotFound
	}
	return yaml, err
}

func (s *Phishlets) ListPhishlets() ([]string, error) {
	rows, err := s.db.db.Query(`SELECT name FROM phishlets WHERE yaml != '' ORDER BY name ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	return names, rows.Err()
}

func (s *Phishlets) SetConfig(cfg *aitm.PhishletConfig) error {
	_, err := s.db.db.Exec(`
		INSERT INTO phishlets (name, base_domain, dns_provider, hostname, spoof_url, enabled)
		VALUES (?,?,?,?,?,?)
		ON CONFLICT(name) DO UPDATE SET
			base_domain=excluded.base_domain,
			dns_provider=excluded.dns_provider,
			hostname=excluded.hostname,
			spoof_url=excluded.spoof_url,
			enabled=excluded.enabled`,
		cfg.Name, cfg.BaseDomain, cfg.DNSProvider, cfg.Hostname,
		cfg.SpoofURL, cfg.Enabled,
	)
	return err
}

func (s *Phishlets) GetConfig(name string) (*aitm.PhishletConfig, error) {
	row := s.db.db.QueryRow(`SELECT
		name, base_domain, dns_provider, hostname, spoof_url, enabled
		FROM phishlets WHERE name = ?`, name)
	cfg, err := scanConfig(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, aitm.ErrNotFound
	}
	return cfg, err
}

func (s *Phishlets) ListConfigs(filter aitm.PhishletFilter) ([]*aitm.PhishletConfig, error) {
	query := `SELECT name, base_domain, dns_provider, hostname, spoof_url, enabled
		FROM phishlets`

	var conditions []string
	var args []any
	if filter.Enabled != nil {
		conditions = append(conditions, "enabled = ?")
		args = append(args, *filter.Enabled)
	}
	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}
	query += " ORDER BY name ASC"

	rows, err := s.db.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*aitm.PhishletConfig
	for rows.Next() {
		cfg, err := scanConfig(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, cfg)
	}
	return out, rows.Err()
}

func (s *Phishlets) DeletePhishlet(name string) error {
	res, err := s.db.db.Exec(`DELETE FROM phishlets WHERE name = ?`, name)
	if err != nil {
		return err
	}
	return requireOneRow(res)
}

func scanConfig(row scanner) (*aitm.PhishletConfig, error) {
	var cfg aitm.PhishletConfig
	err := row.Scan(
		&cfg.Name, &cfg.BaseDomain, &cfg.DNSProvider, &cfg.Hostname,
		&cfg.SpoofURL, &cfg.Enabled,
	)
	return &cfg, err
}
