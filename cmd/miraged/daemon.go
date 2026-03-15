package main

import (
	"log/slog"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/config"
	"github.com/travisbale/mirage/internal/events"
	"github.com/travisbale/mirage/internal/phishlet"
	"github.com/travisbale/mirage/internal/proxy"
	"github.com/travisbale/mirage/internal/store/sqlite"
)

// Daemon is the fully-wired daemon. One instance per process.
// Fields are populated by Init() in dependency order and consumed by Run(),
// Reload(), and Shutdown(). No field is accessed before its initialisation step.
type Daemon struct {
	configPath string
	developer  bool
	log        *slog.Logger

	cfg *config.Config

	// Infrastructure.
	db                *sqlite.DB
	bus               *events.Bus
	dnsService        *aitm.DNSService
	watcher           *phishlet.Watcher
	phishletReloadSub <-chan aitm.Event // closed on shutdown to stop the reload goroutine

	// Proxy.
	proxy *proxy.AITMProxy

	// Services needed by health check and reload.
	phishletStore aitm.PhishletStore
	sessionSvc    *aitm.SessionService
}
