package phishlet_test

import (
	"errors"
	"log/slog"
	"testing"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/phishlet"
)

type nopLureStore struct{}

func (s *nopLureStore) ListLures() ([]*aitm.Lure, error) { return nil, nil }

func newTestResolver() *phishlet.Resolver {
	return phishlet.NewResolver(&nopLureStore{}, slog.Default())
}

func cp(name, baseDomain, hostname string, enabled bool, proxyHosts []aitm.ProxyHost) *aitm.ConfiguredPhishlet {
	return &aitm.ConfiguredPhishlet{
		Definition: &aitm.Phishlet{
			Name:       name,
			ProxyHosts: proxyHosts,
		},
		Config: &aitm.PhishletConfig{
			Name:       name,
			BaseDomain: baseDomain,
			Hostname:   hostname,
			Enabled:    enabled,
		},
	}
}

func TestResolveHostname_LandingHost(t *testing.T) {
	r := newTestResolver()

	p := cp("test", "phish.example.com", "login.phish.example.com", true, []aitm.ProxyHost{
		{PhishSubdomain: "login", Domain: "target.com", IsLanding: true},
	})
	r.Register(p)

	got, _, err := r.ResolveHostname("login.phish.example.com", "/")
	if err != nil {
		t.Fatalf("ResolveHostname: %v", err)
	}
	if got == nil {
		t.Fatal("expected phishlet, got nil")
	}
	if got.Definition.Name != "test" {
		t.Errorf("Name = %q, want %q", got.Definition.Name, "test")
	}
}

func TestResolveHostname_NonLandingHost(t *testing.T) {
	r := newTestResolver()

	p := cp("multi", "phish.example.com", "login.phish.example.com", true, []aitm.ProxyHost{
		{PhishSubdomain: "login", Domain: "target.com", IsLanding: true},
		{PhishSubdomain: "api", Domain: "target.com"},
	})
	r.Register(p)

	// The non-landing host should also resolve to the same phishlet.
	got, _, err := r.ResolveHostname("api.phish.example.com", "/")
	if err != nil {
		t.Fatalf("ResolveHostname: %v", err)
	}
	if got == nil {
		t.Fatal("expected phishlet for non-landing host, got nil")
	}
	if got.Definition.Name != "multi" {
		t.Errorf("Name = %q, want %q", got.Definition.Name, "multi")
	}
}

func TestResolveHostname_UnknownHost(t *testing.T) {
	r := newTestResolver()

	p := cp("test", "phish.example.com", "login.phish.example.com", true, []aitm.ProxyHost{
		{PhishSubdomain: "login", Domain: "target.com", IsLanding: true},
	})
	r.Register(p)

	_, _, err := r.ResolveHostname("unknown.phish.example.com", "/")
	if !errors.Is(err, aitm.ErrNotFound) {
		t.Errorf("expected ErrNotFound for unknown host, got %v", err)
	}
}

func TestResolveHostname_DisabledPhishlet(t *testing.T) {
	r := newTestResolver()

	p := cp("test", "phish.example.com", "login.phish.example.com", false, []aitm.ProxyHost{
		{PhishSubdomain: "login", Domain: "target.com", IsLanding: true},
		{PhishSubdomain: "api", Domain: "target.com"},
	})
	r.Register(p)

	_, _, err := r.ResolveHostname("login.phish.example.com", "/")
	if !errors.Is(err, aitm.ErrNotFound) {
		t.Errorf("expected ErrNotFound for disabled phishlet, got %v", err)
	}

	_, _, err = r.ResolveHostname("api.phish.example.com", "/")
	if !errors.Is(err, aitm.ErrNotFound) {
		t.Errorf("expected ErrNotFound for disabled phishlet non-landing host, got %v", err)
	}
}

func TestResolveHostname_CleanupOnReregister(t *testing.T) {
	r := newTestResolver()

	// Register with two proxy hosts.
	p := cp("multi", "phish.example.com", "login.phish.example.com", true, []aitm.ProxyHost{
		{PhishSubdomain: "login", Domain: "target.com", IsLanding: true},
		{PhishSubdomain: "api", Domain: "target.com"},
	})
	r.Register(p)

	// Re-register with only one proxy host (simulates phishlet YAML change).
	p2 := cp("multi", "phish.example.com", "login.phish.example.com", true, []aitm.ProxyHost{
		{PhishSubdomain: "login", Domain: "target.com", IsLanding: true},
	})
	r.Register(p2)

	// The old api host should no longer resolve.
	_, _, err := r.ResolveHostname("api.phish.example.com", "/")
	if !errors.Is(err, aitm.ErrNotFound) {
		t.Errorf("expected ErrNotFound for removed proxy host, got %v", err)
	}

	// The landing host should still work.
	got, _, err := r.ResolveHostname("login.phish.example.com", "/")
	if err != nil {
		t.Fatalf("ResolveHostname: %v", err)
	}
	if got.Definition.Name != "multi" {
		t.Errorf("Name = %q, want %q", got.Definition.Name, "multi")
	}
}
