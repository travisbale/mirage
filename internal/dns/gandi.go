package dns

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const gandiBaseURL = "https://api.gandi.net/v5/livedns"

// GandiDNSProvider manages records via the Gandi LiveDNS REST API.
type GandiDNSProvider struct {
	apiKey  string
	baseURL string
	client  *http.Client
}

// NewGandiDNSProvider constructs a provider using the given Gandi API key.
func NewGandiDNSProvider(apiKey string) (*GandiDNSProvider, error) {
	return &GandiDNSProvider{
		apiKey:  apiKey,
		baseURL: gandiBaseURL,
		client:  &http.Client{Timeout: 15 * time.Second},
	}, nil
}

func (p *GandiDNSProvider) do(ctx context.Context, method, url string, body any) (*http.Response, error) {
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			return nil, err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, url, &buf)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Apikey "+p.apiKey)
	req.Header.Set("Content-Type", "application/json")
	return p.client.Do(req)
}

type gandiRRSet struct {
	RRSetValues []string `json:"rrset_values"`
	RRSetTTL    int      `json:"rrset_ttl,omitempty"`
}

func (p *GandiDNSProvider) putRRSet(ctx context.Context, zone, name, typ, value string, ttl int) error {
	if ttl == 0 {
		ttl = 300
	}
	endpoint := fmt.Sprintf("%s/domains/%s/records/%s/%s", p.baseURL, zone, name, typ)
	resp, err := p.do(ctx, http.MethodPut, endpoint, gandiRRSet{
		RRSetValues: []string{value},
		RRSetTTL:    ttl,
	})
	if err != nil {
		return fmt.Errorf("gandi: %s %s: %w", typ, name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("gandi: %s %s: HTTP %d", typ, name, resp.StatusCode)
	}
	return nil
}

func (p *GandiDNSProvider) CreateRecord(zone, name, typ, value string, ttl int) error {
	return p.putRRSet(context.Background(), zone, name, typ, value, ttl)
}

func (p *GandiDNSProvider) UpdateRecord(zone, name, typ, value string, ttl int) error {
	return p.putRRSet(context.Background(), zone, name, typ, value, ttl)
}

func (p *GandiDNSProvider) DeleteRecord(zone, name, typ string) error {
	ctx := context.Background()
	endpoint := fmt.Sprintf("%s/domains/%s/records/%s/%s", p.baseURL, zone, name, typ)
	resp, err := p.do(ctx, http.MethodDelete, endpoint, nil)
	if err != nil {
		return fmt.Errorf("gandi: delete %s %s: %w", typ, name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil // idempotent
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("gandi: delete %s %s: HTTP %d", typ, name, resp.StatusCode)
	}
	return nil
}

func (p *GandiDNSProvider) Present(domain, token, keyAuth string) error {
	zone := extractZone(domain)
	label := acmeChallengeKey(domain, zone)
	return p.putRRSet(context.Background(), zone, label, "TXT", `"`+acmeTXTValue(keyAuth)+`"`, 120)
}

func (p *GandiDNSProvider) CleanUp(domain, token, keyAuth string) error {
	zone := extractZone(domain)
	label := acmeChallengeKey(domain, zone)
	return p.DeleteRecord(zone, label, "TXT")
}

func (p *GandiDNSProvider) Ping() error {
	ctx := context.Background()
	endpoint := fmt.Sprintf("%s/domains", p.baseURL)
	resp, err := p.do(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("gandi: ping failed: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("gandi: invalid API key")
	}
	return nil
}

func (p *GandiDNSProvider) Name() string { return "gandi" }

// SetBaseURL overrides the default Gandi API base URL. Used in tests.
func (p *GandiDNSProvider) SetBaseURL(url string) { p.baseURL = url }
