package dns

import (
	"context"
	"fmt"

	"github.com/cloudflare/cloudflare-go"

	"github.com/travisbale/mirage/internal/aitm"
)

// cloudflareTTLAuto tells the Cloudflare API to use automatic TTL management.
const cloudflareTTLAuto = 1

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

// lookupZoneID resolves a zone name to its Cloudflare zone ID.
// Note: ZoneIDByName does not accept a context (SDK limitation), so the
// ctx parameter is accepted for signature consistency but not honoured here.
func (p *CloudflareDNSProvider) lookupZoneID(ctx context.Context, zone string) (string, error) {
	id, err := p.client.ZoneIDByName(zone)
	if err != nil {
		return "", fmt.Errorf("cloudflare: resolving zone ID for %q: %w", zone, err)
	}
	return id, nil
}

func (p *CloudflareDNSProvider) CreateRecord(ctx context.Context, zone, name, typ, value string, ttl int) error {
	zoneID, err := p.lookupZoneID(ctx, zone)
	if err != nil {
		return err
	}
	if ttl == 0 {
		ttl = cloudflareTTLAuto
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

func (p *CloudflareDNSProvider) UpdateRecord(ctx context.Context, zone, name, typ, value string, ttl int) error {
	zoneID, err := p.lookupZoneID(ctx, zone)
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
		ttl = cloudflareTTLAuto
	}
	_, err = p.client.UpdateDNSRecord(ctx, cloudflare.ZoneIdentifier(zoneID), cloudflare.UpdateDNSRecordParams{
		ID:      records[0].ID,
		Type:    typ,
		Name:    name,
		Content: value,
		TTL:     ttl,
	})
	if err != nil {
		return fmt.Errorf("cloudflare: UpdateRecord %s %s: %w", typ, name, err)
	}
	return nil
}

func (p *CloudflareDNSProvider) DeleteRecord(ctx context.Context, zone, name, typ string) error {
	zoneID, err := p.lookupZoneID(ctx, zone)
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
	if err := p.client.DeleteDNSRecord(ctx, cloudflare.ZoneIdentifier(zoneID), records[0].ID); err != nil {
		return fmt.Errorf("cloudflare: DeleteRecord %s %s: %w", typ, name, err)
	}
	return nil
}

func (p *CloudflareDNSProvider) Present(ctx context.Context, domain, token, keyAuth string) error {
	zone := extractZone(domain)
	label := acmeChallengeKey(domain, zone)
	return p.CreateRecord(ctx, zone, label, "TXT", acmeTXTValue(keyAuth), 120)
}

func (p *CloudflareDNSProvider) CleanUp(ctx context.Context, domain, token, keyAuth string) error {
	zone := extractZone(domain)
	label := acmeChallengeKey(domain, zone)
	return p.DeleteRecord(ctx, zone, label, "TXT")
}

func (p *CloudflareDNSProvider) Ping(ctx context.Context) error {
	_, err := p.client.UserDetails(ctx)
	if err != nil {
		return fmt.Errorf("cloudflare: ping failed: %w", err)
	}
	return nil
}

func (p *CloudflareDNSProvider) Name() string { return "cloudflare" }
