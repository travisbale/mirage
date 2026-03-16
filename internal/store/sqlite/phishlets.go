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

func (s *Phishlets) GetPhishletDeployment(name string) (*aitm.PhishletDeployment, error) {
	row := s.db.db.QueryRow(`SELECT
		name, base_domain, dns_provider, hostname, unauth_url, spoof_url, enabled, hidden
		FROM phishlet_configs WHERE name = ?`, name)
	deployment, err := scanPhishletDeployment(row)
	if err == sql.ErrNoRows {
		return nil, aitm.ErrNotFound
	}
	return deployment, err
}

func (s *Phishlets) SetPhishletDeployment(deployment *aitm.PhishletDeployment) error {
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
		deployment.Name, deployment.BaseDomain, deployment.DNSProvider, deployment.Hostname,
		deployment.UnauthURL, deployment.SpoofURL, deployment.Enabled, deployment.Hidden,
	)
	return err
}

func (s *Phishlets) ListPhishletDeployments() ([]*aitm.PhishletDeployment, error) {
	rows, err := s.db.db.Query(`SELECT
		name, base_domain, dns_provider, hostname, unauth_url, spoof_url, enabled, hidden
		FROM phishlet_configs ORDER BY name ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*aitm.PhishletDeployment
	for rows.Next() {
		deployment, err := scanPhishletDeployment(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, deployment)
	}
	return out, rows.Err()
}

func (s *Phishlets) DeletePhishletDeployment(name string) error {
	res, err := s.db.db.Exec(`DELETE FROM phishlet_configs WHERE name = ?`, name)
	if err != nil {
		return err
	}
	return requireOneRow(res)
}

func scanPhishletDeployment(row scanner) (*aitm.PhishletDeployment, error) {
	var deployment aitm.PhishletDeployment
	err := row.Scan(
		&deployment.Name, &deployment.BaseDomain, &deployment.DNSProvider, &deployment.Hostname,
		&deployment.UnauthURL, &deployment.SpoofURL, &deployment.Enabled, &deployment.Hidden,
	)
	return &deployment, err
}
