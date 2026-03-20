package sqlite

import (
	"database/sql"
	"errors"

	"github.com/travisbale/mirage/internal/aitm"
)

// Phishlets implements the phishletStore interface defined in the aitm package.
// Only operator config fields are persisted; compiled rule fields are never stored.
type Phishlets struct{ db *DB }

func NewPhishletStore(db *DB) *Phishlets { return &Phishlets{db: db} }

func (s *Phishlets) GetPhishlet(name string) (*aitm.Phishlet, error) {
	row := s.db.db.QueryRow(`SELECT
		name, base_domain, dns_provider, hostname, spoof_url, enabled, hidden
		FROM phishlet_configs WHERE name = ?`, name)
	p, err := scanPhishlet(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, aitm.ErrNotFound
	}
	return p, err
}

func (s *Phishlets) SetPhishlet(p *aitm.Phishlet) error {
	_, err := s.db.db.Exec(`
		INSERT INTO phishlet_configs
			(name, base_domain, dns_provider, hostname, spoof_url, enabled, hidden)
		VALUES (?,?,?,?,?,?,?)
		ON CONFLICT(name) DO UPDATE SET
			base_domain=excluded.base_domain,
			dns_provider=excluded.dns_provider,
			hostname=excluded.hostname,
			spoof_url=excluded.spoof_url,
			enabled=excluded.enabled,
			hidden=excluded.hidden`,
		p.Name, p.BaseDomain, p.DNSProvider, p.Hostname,
		p.SpoofURL, p.Enabled, p.Hidden,
	)
	return err
}

func (s *Phishlets) ListPhishlets() ([]*aitm.Phishlet, error) {
	rows, err := s.db.db.Query(`SELECT
		name, base_domain, dns_provider, hostname, spoof_url, enabled, hidden
		FROM phishlet_configs ORDER BY name ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*aitm.Phishlet
	for rows.Next() {
		p, err := scanPhishlet(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Phishlets) DeletePhishlet(name string) error {
	res, err := s.db.db.Exec(`DELETE FROM phishlet_configs WHERE name = ?`, name)
	if err != nil {
		return err
	}
	return requireOneRow(res)
}

func scanPhishlet(row scanner) (*aitm.Phishlet, error) {
	var p aitm.Phishlet
	err := row.Scan(
		&p.Name, &p.BaseDomain, &p.DNSProvider, &p.Hostname,
		&p.SpoofURL, &p.Enabled, &p.Hidden,
	)
	return &p, err
}
