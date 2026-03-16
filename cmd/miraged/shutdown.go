package main

import (
	"context"

	"github.com/travisbale/mirage/internal/aitm"
)

// Shutdown tears down all subsystems in reverse dependency order.
// Called after Run returns.
func (d *Daemon) Shutdown() {
	d.logger.Info("shutting down")

	// Unsubscribe phishlet reload handler (closes goroutine started by SubscribeFunc).
	if d.phishletReloadSub != nil {
		d.bus.Unsubscribe(aitm.EventPhishletReloaded, d.phishletReloadSub)
	}

	// Stop phishlet file watcher.
	if d.watcher != nil {
		if err := d.watcher.Close(); err != nil {
			d.logger.Error("watcher close error", "error", err)
		}
	}

	// Close the store (flushes WAL, closes SQLite connection).
	d.logger.Info("closing store")
	if err := d.db.Close(); err != nil {
		d.logger.Error("store close error", "error", err)
	}

	// Shut down JS obfuscator sidecar processes if running.
	if d.obfuscator != nil {
		if err := d.obfuscator.Shutdown(context.Background()); err != nil {
			d.logger.Error("obfuscator shutdown error", "error", err)
		}
	}

	d.logger.Info("shutdown complete")
}
