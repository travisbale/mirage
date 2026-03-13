package dns

import (
	"context"
	"fmt"

	"github.com/cloudflare/cloudflare-go"

	"github.com/travisbale/mirage/internal/aitm"
)

// CloudflareDNSProvider manages records via the Cloudflare API v4.
type CloudflareDNSProvider struct {
	client *cloudflare.API
}

// NewCloudflareDNSProvider constructs a provider using the given API token.
// The token must have Zone.DNS:Edit permissions on the relevant zones.
func NewCloudflareDNSProvider(apiToken string, opts ...cloudflare.Option) (*CloudflareDNSProvider, error) {
	api, err := cloudflare.NewWithAPIToken(apiToken, opts...)
	if err != nil {
		return nil, fmt.Errorf("cloudflare: constructing client: %w", err)
	}
	return &CloudflareDNSProvider{client: api}, nil
}

func (p *CloudflareDNSProvider) zoneID(ctx context.Context, zone string) (string, error) {
	id, err := p.client.ZoneIDByName(zone)
	if err != nil {
		return "", fmt.Errorf("cloudflare: resolving zone ID for %q: %w", zone, err)
	}
	return id, nil
}

func (p *CloudflareDNSProvider) CreateRecord(zone, name, typ, value string, ttl int) error {
	ctx := context.Background()
	zoneID, err := p.zoneID(ctx, zone)
	if err != nil {
		return err
	}
	if ttl == 0 {
		ttl = 1 // Cloudflare: 1 = auto
	}
	_, err = p.client.CreateDNSRecord(ctx, cloudflare.ZoneIdentifier(zoneID), cloudflare.CreateDNSRecordParams{
		Type:    typ,
		Name:    name,
		Content: value,
		TTL:     ttl,
	})
	if err != nil {
		return fmt.Errorf("cloudflare: CreateRecord %s %s: %w", typ, name, err)
	}
	return nil
}

func (p *CloudflareDNSProvider) UpdateRecord(zone, name, typ, value string, ttl int) error {
	ctx := context.Background()
	zoneID, err := p.zoneID(ctx, zone)
	if err != nil {
		return err
	}
	records, _, err := p.client.ListDNSRecords(ctx, cloudflare.ZoneIdentifier(zoneID),
		cloudflare.ListDNSRecordsParams{Type: typ, Name: name + "." + zone},
	)
	if err != nil {
		return fmt.Errorf("cloudflare: listing records to update: %w", err)
	}
	if len(records) == 0 {
		return fmt.Errorf("%w: %s %s", aitm.ErrRecordNotFound, typ, name)
	}
	if ttl == 0 {
		ttl = 1
	}
	_, err = p.client.UpdateDNSRecord(ctx, cloudflare.ZoneIdentifier(zoneID), cloudflare.UpdateDNSRecordParams{
		ID:      records[0].ID,
		Type:    typ,
		Name:    name,
		Content: value,
		TTL:     ttl,
	})
	return err
}

func (p *CloudflareDNSProvider) DeleteRecord(zone, name, typ string) error {
	ctx := context.Background()
	zoneID, err := p.zoneID(ctx, zone)
	if err != nil {
		return err
	}
	records, _, err := p.client.ListDNSRecords(ctx, cloudflare.ZoneIdentifier(zoneID),
		cloudflare.ListDNSRecordsParams{Type: typ, Name: name + "." + zone},
	)
	if err != nil {
		return fmt.Errorf("cloudflare: listing records to delete: %w", err)
	}
	if len(records) == 0 {
		return nil // idempotent
	}
	return p.client.DeleteDNSRecord(ctx, cloudflare.ZoneIdentifier(zoneID), records[0].ID)
}

func (p *CloudflareDNSProvider) Present(domain, token, keyAuth string) error {
	zone := extractZone(domain)
	label := acmeChallengeKey(domain, zone)
	return p.CreateRecord(zone, label, "TXT", acmeTXTValue(keyAuth), 120)
}

func (p *CloudflareDNSProvider) CleanUp(domain, token, keyAuth string) error {
	zone := extractZone(domain)
	label := acmeChallengeKey(domain, zone)
	return p.DeleteRecord(zone, label, "TXT")
}

func (p *CloudflareDNSProvider) Ping() error {
	_, err := p.client.UserDetails(context.Background())
	if err != nil {
		return fmt.Errorf("cloudflare: ping failed: %w", err)
	}
	return nil
}

func (p *CloudflareDNSProvider) Name() string { return "cloudflare" }
