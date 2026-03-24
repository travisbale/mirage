package aitm_test

import (
	"context"
	"log/slog"
	"testing"

	"github.com/travisbale/mirage/internal/aitm"
)

type nopPhishletStore struct{}

func (s *nopPhishletStore) GetPhishlet(string) (*aitm.Phishlet, error) { return nil, aitm.ErrNotFound }
func (s *nopPhishletStore) SetPhishlet(*aitm.Phishlet) error           { return nil }
func (s *nopPhishletStore) ListPhishlets() ([]*aitm.Phishlet, error)   { return nil, nil }
func (s *nopPhishletStore) DeletePhishlet(string) error                { return nil }

type nopDNSReconciler struct{}

func (r nopDNSReconciler) Reconcile(context.Context, []aitm.PhishletRecord) error     { return nil }
func (r nopDNSReconciler) RemoveRecords(context.Context, []aitm.PhishletRecord) error { return nil }

type nopLureStore struct{}

func (s *nopLureStore) CreateLure(*aitm.Lure) error        { return nil }
func (s *nopLureStore) GetLure(string) (*aitm.Lure, error) { return nil, aitm.ErrNotFound }
func (s *nopLureStore) UpdateLure(*aitm.Lure) error        { return nil }
func (s *nopLureStore) DeleteLure(string) error            { return nil }
func (s *nopLureStore) ListLures() ([]*aitm.Lure, error)   { return nil, nil }

func newTestPhishletService() *aitm.PhishletService {
	bus := &stubBus{}
	return aitm.NewPhishletService(&nopPhishletStore{}, bus, nopDNSReconciler{}, &nopLureStore{}, slog.Default())
}

func TestResolveHostname_LandingHost(t *testing.T) {
	svc := newTestPhishletService()

	p := &aitm.Phishlet{
		Name:       "test",
		BaseDomain: "phish.example.com",
		Hostname:   "login.phish.example.com",
		Enabled:    true,
		ProxyHosts: []aitm.ProxyHost{
			{PhishSubdomain: "login", Domain: "target.com", IsLanding: true},
		},
	}
	svc.Register(p)

	got, _, err := svc.ResolveHostname("login.phish.example.com", "/")
	if err != nil {
		t.Fatalf("ResolveHostname: %v", err)
	}
	if got == nil {
		t.Fatal("expected phishlet, got nil")
	}
	if got.Name != "test" {
		t.Errorf("Name = %q, want %q", got.Name, "test")
	}
}

func TestResolveHostname_NonLandingHost(t *testing.T) {
	svc := newTestPhishletService()

	p := &aitm.Phishlet{
		Name:       "multi",
		BaseDomain: "phish.example.com",
		Hostname:   "login.phish.example.com",
		Enabled:    true,
		ProxyHosts: []aitm.ProxyHost{
			{PhishSubdomain: "login", Domain: "target.com", IsLanding: true},
			{PhishSubdomain: "api", Domain: "target.com"},
		},
	}
	svc.Register(p)

	// The non-landing host should also resolve to the same phishlet.
	got, _, err := svc.ResolveHostname("api.phish.example.com", "/")
	if err != nil {
		t.Fatalf("ResolveHostname: %v", err)
	}
	if got == nil {
		t.Fatal("expected phishlet for non-landing host, got nil")
	}
	if got.Name != "multi" {
		t.Errorf("Name = %q, want %q", got.Name, "multi")
	}
}

func TestResolveHostname_UnknownHost(t *testing.T) {
	svc := newTestPhishletService()

	p := &aitm.Phishlet{
		Name:       "test",
		BaseDomain: "phish.example.com",
		Hostname:   "login.phish.example.com",
		Enabled:    true,
		ProxyHosts: []aitm.ProxyHost{
			{PhishSubdomain: "login", Domain: "target.com", IsLanding: true},
		},
	}
	svc.Register(p)

	got, _, err := svc.ResolveHostname("unknown.phish.example.com", "/")
	if err != nil {
		t.Fatalf("ResolveHostname: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil for unknown host, got %q", got.Name)
	}
}

func TestResolveHostname_DisabledPhishlet(t *testing.T) {
	svc := newTestPhishletService()

	p := &aitm.Phishlet{
		Name:       "test",
		BaseDomain: "phish.example.com",
		Hostname:   "login.phish.example.com",
		Enabled:    false,
		ProxyHosts: []aitm.ProxyHost{
			{PhishSubdomain: "login", Domain: "target.com", IsLanding: true},
			{PhishSubdomain: "api", Domain: "target.com"},
		},
	}
	svc.Register(p)

	got, _, _ := svc.ResolveHostname("login.phish.example.com", "/")
	if got != nil {
		t.Error("expected nil for disabled phishlet")
	}

	got, _, _ = svc.ResolveHostname("api.phish.example.com", "/")
	if got != nil {
		t.Error("expected nil for disabled phishlet non-landing host")
	}
}

func TestResolveHostname_CleanupOnReregister(t *testing.T) {
	svc := newTestPhishletService()

	// Register with two proxy hosts.
	p := &aitm.Phishlet{
		Name:       "multi",
		BaseDomain: "phish.example.com",
		Hostname:   "login.phish.example.com",
		Enabled:    true,
		ProxyHosts: []aitm.ProxyHost{
			{PhishSubdomain: "login", Domain: "target.com", IsLanding: true},
			{PhishSubdomain: "api", Domain: "target.com"},
		},
	}
	svc.Register(p)

	// Re-register with only one proxy host (simulates phishlet YAML change).
	p2 := &aitm.Phishlet{
		Name:       "multi",
		BaseDomain: "phish.example.com",
		Hostname:   "login.phish.example.com",
		Enabled:    true,
		ProxyHosts: []aitm.ProxyHost{
			{PhishSubdomain: "login", Domain: "target.com", IsLanding: true},
		},
	}
	svc.Register(p2)

	// The old api host should no longer resolve.
	got, _, _ := svc.ResolveHostname("api.phish.example.com", "/")
	if got != nil {
		t.Error("expected nil for removed proxy host, got phishlet")
	}

	// The landing host should still work.
	got, _, _ = svc.ResolveHostname("login.phish.example.com", "/")
	if got == nil {
		t.Fatal("expected phishlet for landing host after re-register")
	}
}
