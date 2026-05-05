package aitm_test

import (
	"context"
	"testing"

	"github.com/travisbale/mirage/internal/aitm"
)

// ── Phishlet.MatchesHost ─────────────────────────────────────────────────────

func TestMatchesHost_Match(t *testing.T) {
	phishlet := &aitm.Phishlet{
		ProxyHosts: []aitm.ProxyHost{
			{PhishSubdomain: "login", Domain: "microsoft.com"},
		},
	}
	if !phishlet.MatchesHost("login.phish.example.com", "phish.example.com") {
		t.Error("expected hostname to match")
	}
}

func TestMatchesHost_NoMatch(t *testing.T) {
	phishlet := &aitm.Phishlet{
		ProxyHosts: []aitm.ProxyHost{
			{PhishSubdomain: "login", Domain: "microsoft.com"},
		},
	}
	if phishlet.MatchesHost("other.phish.example.com", "phish.example.com") {
		t.Error("expected hostname not to match")
	}
}

func TestMatchesHost_MultipleHosts(t *testing.T) {
	phishlet := &aitm.Phishlet{
		ProxyHosts: []aitm.ProxyHost{
			{PhishSubdomain: "login", Domain: "microsoft.com"},
			{PhishSubdomain: "account", Domain: "microsoft.com"},
		},
	}
	if !phishlet.MatchesHost("account.phish.example.com", "phish.example.com") {
		t.Error("expected second proxy host to match")
	}
}

// ── Phishlet.FindLanding ─────────────────────────────────────────────────────

func TestFindLanding_Present(t *testing.T) {
	phishlet := &aitm.Phishlet{
		ProxyHosts: []aitm.ProxyHost{
			{PhishSubdomain: "api", Domain: "microsoft.com", IsLanding: false},
			{PhishSubdomain: "login", Domain: "microsoft.com", IsLanding: true},
		},
	}
	landing := phishlet.FindLanding()
	if landing == nil {
		t.Fatal("expected landing host, got nil")
	}
	if landing.PhishSubdomain != "login" {
		t.Errorf("expected login landing host, got %q", landing.PhishSubdomain)
	}
}

func TestFindLanding_Absent(t *testing.T) {
	phishlet := &aitm.Phishlet{
		ProxyHosts: []aitm.ProxyHost{
			{PhishSubdomain: "api", Domain: "microsoft.com", IsLanding: false},
		},
	}
	if phishlet.FindLanding() != nil {
		t.Error("expected nil when no landing host exists")
	}
}

// ── ProxyHost.OriginHost ─────────────────────────────────────────────────────

func TestOriginHost_WithSubdomain(t *testing.T) {
	host := aitm.ProxyHost{OrigSubdomain: "login", Domain: "microsoftonline.com"}
	if got := host.OriginHost(); got != "login.microsoftonline.com" {
		t.Errorf("got %q, want %q", got, "login.microsoftonline.com")
	}
}

func TestOriginHost_WithoutSubdomain(t *testing.T) {
	host := aitm.ProxyHost{Domain: "example.com"}
	if got := host.OriginHost(); got != "example.com" {
		t.Errorf("got %q, want %q", got, "example.com")
	}
}

// ── SubFilter.MatchesMIME ────────────────────────────────────────────────────

func TestMatchesMIME_Match(t *testing.T) {
	filter := aitm.SubFilter{MimeTypes: []string{"text/html", "application/json"}}
	if !filter.MatchesMIME("text/html; charset=utf-8") {
		t.Error("expected text/html to match with prefix")
	}
}

func TestMatchesMIME_NoMatch(t *testing.T) {
	filter := aitm.SubFilter{MimeTypes: []string{"text/html"}}
	if filter.MatchesMIME("application/json") {
		t.Error("expected application/json not to match text/html filter")
	}
}

// ── PhishletService ──────────────────────────────────────────────────────────

// stubPhishletStore implements the subset of phishletStore needed by ReconcileAll.
type stubPhishletStore struct {
	configs []*aitm.PhishletConfig
}

func (s *stubPhishletStore) SavePhishlet(string, string) error              { return nil }
func (s *stubPhishletStore) GetPhishlet(string) (string, error)             { return "", nil }
func (s *stubPhishletStore) ListPhishlets() ([]string, error)               { return nil, nil }
func (s *stubPhishletStore) SetConfig(*aitm.PhishletConfig) error           { return nil }
func (s *stubPhishletStore) GetConfig(string) (*aitm.PhishletConfig, error) { return nil, nil }
func (s *stubPhishletStore) DeletePhishlet(string) error                    { return nil }

func (s *stubPhishletStore) ListConfigs(filter aitm.PhishletFilter) ([]*aitm.PhishletConfig, error) {
	if filter.Enabled != nil && *filter.Enabled {
		var out []*aitm.PhishletConfig
		for _, c := range s.configs {
			if c.Enabled {
				out = append(out, c)
			}
		}
		return out, nil
	}
	return s.configs, nil
}

// stubResolver returns pre-registered ConfiguredPhishlets by name.
type stubResolver struct {
	phishlets map[string]*aitm.ConfiguredPhishlet
}

func (r *stubResolver) Get(name string) *aitm.ConfiguredPhishlet { return r.phishlets[name] }
func (r *stubResolver) Register(*aitm.ConfiguredPhishlet)        {}
func (r *stubResolver) OwnerOf(string) string                    { return "" }
func (r *stubResolver) ResolveHostname(string, string) (*aitm.ConfiguredPhishlet, *aitm.Lure, error) {
	return nil, nil, nil
}
func (r *stubResolver) LoadLuresFromDB() error { return nil }
func (r *stubResolver) InvalidateLures()       {}

// stubDNSReconciler records the records passed to Reconcile.
type stubDNSReconciler struct {
	reconciled []aitm.PhishletRecord
}

func (r *stubDNSReconciler) Reconcile(_ context.Context, records []aitm.PhishletRecord) error {
	r.reconciled = append(r.reconciled, records...)
	return nil
}
func (r *stubDNSReconciler) RemoveRecords(context.Context, []aitm.PhishletRecord) error {
	return nil
}

func TestPhishletService_ReconcileAll(t *testing.T) {
	store := &stubPhishletStore{
		configs: []*aitm.PhishletConfig{
			{Name: "site-a", BaseDomain: "phish.com", Enabled: true},
			{Name: "site-b", BaseDomain: "evil.net", Enabled: true},
			{Name: "disabled", BaseDomain: "off.com", Enabled: false},
		},
	}

	resolver := &stubResolver{
		phishlets: map[string]*aitm.ConfiguredPhishlet{
			"site-a": {
				Definition: &aitm.Phishlet{
					Name: "site-a",
					ProxyHosts: []aitm.ProxyHost{
						{PhishSubdomain: "login", OrigSubdomain: "login", Domain: "target-a.com"},
					},
				},
				Config: &aitm.PhishletConfig{Name: "site-a", BaseDomain: "phish.com", Enabled: true},
			},
			"site-b": {
				Definition: &aitm.Phishlet{
					Name: "site-b",
					ProxyHosts: []aitm.ProxyHost{
						{PhishSubdomain: "login", OrigSubdomain: "login", Domain: "target-b.com"},
						{PhishSubdomain: "api", OrigSubdomain: "api", Domain: "target-b.com"},
					},
				},
				Config: &aitm.PhishletConfig{Name: "site-b", BaseDomain: "evil.net", Enabled: true},
			},
		},
	}

	dns := &stubDNSReconciler{}

	svc := &aitm.PhishletService{
		Store:    store,
		Bus:      &stubBus{},
		DNS:      dns,
		Resolver: resolver,
	}

	if err := svc.ReconcileAll(context.Background()); err != nil {
		t.Fatalf("ReconcileAll: %v", err)
	}

	// site-a has 1 proxy host, site-b has 2, disabled is skipped.
	if len(dns.reconciled) != 3 {
		t.Fatalf("expected 3 records reconciled, got %d", len(dns.reconciled))
	}

	names := map[string]bool{}
	for _, r := range dns.reconciled {
		names[r.Name] = true
	}
	if !names["login.phish.com"] {
		t.Error("expected login.phish.com record")
	}
	if !names["login.evil.net"] {
		t.Error("expected login.evil.net record")
	}
	if !names["api.evil.net"] {
		t.Error("expected api.evil.net record")
	}
}

func TestPhishletService_ReconcileAll_NoEnabledPhishlets(t *testing.T) {
	store := &stubPhishletStore{configs: nil}
	dns := &stubDNSReconciler{}

	svc := &aitm.PhishletService{
		Store:    store,
		Bus:      &stubBus{},
		DNS:      dns,
		Resolver: &stubResolver{phishlets: map[string]*aitm.ConfiguredPhishlet{}},
	}

	if err := svc.ReconcileAll(context.Background()); err != nil {
		t.Fatalf("ReconcileAll: %v", err)
	}

	if len(dns.reconciled) != 0 {
		t.Errorf("expected 0 records, got %d", len(dns.reconciled))
	}
}
