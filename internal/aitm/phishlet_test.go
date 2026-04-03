package aitm_test

import (
	"context"
	"testing"

	"github.com/travisbale/mirage/internal/aitm"
)

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
