package aitm

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/travisbale/mirage/sdk"
)

// ── stubs ────────────────────────────────────────────────────────────────────

type stubPuppet struct {
	telemetry map[string]any
	err       error
	calls     int
}

func (s *stubPuppet) CollectTelemetry(_ context.Context, _ string) (map[string]any, error) {
	s.calls++
	return s.telemetry, s.err
}

func (s *stubPuppet) Shutdown(_ context.Context) error { return nil }

type stubBuilder struct {
	override string
}

func (s *stubBuilder) BuildOverride(_ map[string]any) string { return s.override }

type stubBus struct {
	ch chan Event
}

func (s *stubBus) Publish(event Event) {}
func (s *stubBus) Subscribe(_ sdk.EventType) (<-chan Event, func()) {
	return s.ch, func() {}
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newTestPuppetService(puppet puppet, builder overrideBuilder) *PuppetService {
	bus := &stubBus{ch: make(chan Event)}
	return NewPuppetService(puppet, builder, bus, PuppetServiceConfig{
		CacheTTL:      time.Hour,
		NavTimeout:    10 * time.Second,
		MaxConcurrent: 2,
	}, discardLogger())
}

// ── GetOverride ──────────────────────────────────────────────────────────────

func TestGetOverride_CacheMiss(t *testing.T) {
	svc := newTestPuppetService(&stubPuppet{}, &stubBuilder{})
	if got := svc.GetOverride("nonexistent"); got != "" {
		t.Errorf("cache miss: got %q, want empty", got)
	}
}

func TestGetOverride_CacheHit(t *testing.T) {
	svc := newTestPuppetService(&stubPuppet{}, &stubBuilder{})
	svc.cache.Store("microsoft", cacheEntry{
		override:  "(function(){/*test*/})();",
		expiresAt: time.Now().Add(time.Hour),
	})

	got := svc.GetOverride("microsoft")
	if got != "(function(){/*test*/})();" {
		t.Errorf("cache hit: got %q, want override script", got)
	}
}

func TestGetOverride_ExpiredEntry(t *testing.T) {
	svc := newTestPuppetService(&stubPuppet{}, &stubBuilder{})
	svc.cache.Store("microsoft", cacheEntry{
		override:  "(function(){/*expired*/})();",
		expiresAt: time.Now().Add(-time.Second),
	})

	if got := svc.GetOverride("microsoft"); got != "" {
		t.Errorf("expired entry: got %q, want empty", got)
	}
	// Verify the expired entry was cleaned up.
	if _, ok := svc.cache.Load("microsoft"); ok {
		t.Error("expired entry should have been deleted from cache")
	}
}

// ── CollectAndCache ──────────────────────────────────────────────────────────

func TestCollectAndCache_Success(t *testing.T) {
	puppet := &stubPuppet{telemetry: map[string]any{"userAgent": "TestAgent"}}
	builder := &stubBuilder{override: "(function(){/*override*/})();"}
	svc := newTestPuppetService(puppet, builder)

	err := svc.CollectAndCache(context.Background(), "microsoft", "https://login.microsoftonline.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if puppet.calls != 1 {
		t.Errorf("expected 1 collect call, got %d", puppet.calls)
	}
	if got := svc.GetOverride("microsoft"); got != "(function(){/*override*/})();" {
		t.Errorf("cached override: got %q, want override script", got)
	}
}

func TestCollectAndCache_PuppetError(t *testing.T) {
	puppet := &stubPuppet{err: fmt.Errorf("chromium crashed")}
	svc := newTestPuppetService(puppet, &stubBuilder{})

	err := svc.CollectAndCache(context.Background(), "microsoft", "https://example.com")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if got := svc.GetOverride("microsoft"); got != "" {
		t.Errorf("should not cache on error: got %q", got)
	}
}

// ── MaxConcurrent default ────────────────────────────────────────────────────

func TestNewPuppetService_DefaultMaxConcurrent(t *testing.T) {
	svc := NewPuppetService(&stubPuppet{}, &stubBuilder{}, &stubBus{ch: make(chan Event)}, PuppetServiceConfig{}, discardLogger())
	if cap(svc.collectC) != 3 {
		t.Errorf("default MaxConcurrent: got %d, want 3", cap(svc.collectC))
	}
}

// ── deriveTargetURL ──────────────────────────────────────────────────────────

func TestDeriveTargetURL_WithLanding(t *testing.T) {
	phishlet := &Phishlet{
		ProxyHosts: []ProxyHost{
			{OrigSubdomain: "login", Domain: "microsoftonline.com", IsLanding: true},
		},
		Login: LoginSpec{Path: "/common/oauth2/authorize"},
	}

	got := deriveTargetURL(phishlet)
	want := "https://login.microsoftonline.com/common/oauth2/authorize"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestDeriveTargetURL_NoLanding(t *testing.T) {
	phishlet := &Phishlet{
		ProxyHosts: []ProxyHost{
			{OrigSubdomain: "login", Domain: "example.com", IsLanding: false},
		},
	}
	if got := deriveTargetURL(phishlet); got != "" {
		t.Errorf("no landing host: got %q, want empty", got)
	}
}

func TestDeriveTargetURL_EmptyPath(t *testing.T) {
	phishlet := &Phishlet{
		ProxyHosts: []ProxyHost{
			{OrigSubdomain: "", Domain: "example.com", IsLanding: true},
		},
		Login: LoginSpec{Path: ""},
	}

	got := deriveTargetURL(phishlet)
	if got != "https://example.com/" {
		t.Errorf("empty path: got %q, want %q", got, "https://example.com/")
	}
}

func TestDeriveTargetURL_NoSubdomain(t *testing.T) {
	phishlet := &Phishlet{
		ProxyHosts: []ProxyHost{
			{Domain: "example.com", IsLanding: true},
		},
		Login: LoginSpec{Path: "/login"},
	}

	got := deriveTargetURL(phishlet)
	if got != "https://example.com/login" {
		t.Errorf("no subdomain: got %q, want %q", got, "https://example.com/login")
	}
}
