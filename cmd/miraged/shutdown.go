package main

import "github.com/travisbale/mirage/internal/aitm"

// Shutdown tears down all subsystems in reverse dependency order.
// Called after Run returns.
func (d *Daemon) Shutdown() {
	d.log.Info("shutting down")

	// Unsubscribe phishlet reload handler (closes goroutine started by SubscribeFunc).
	if d.phishletReloadSub != nil {
		d.bus.Unsubscribe(aitm.EventPhishletReloaded, d.phishletReloadSub)
	}

	// Stop phishlet file watcher.
	if d.watcher != nil {
		if err := d.watcher.Close(); err != nil {
			d.log.Error("watcher close error", "error", err)
		}
	}

	// Close the store (flushes WAL, closes SQLite connection).
	d.log.Info("closing store")
	if err := d.db.Close(); err != nil {
		d.log.Error("store close error", "error", err)
	}

	d.log.Info("shutdown complete")
}
