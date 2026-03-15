package main

import "fmt"

// Reload re-reads the config file and applies live-reloadable settings.
// Settings that require a restart are logged as warnings and skipped.
func (d *Daemon) Reload() error {
	newCfg, err := loadConfig(d.configPath)
	if err != nil {
		return fmt.Errorf("reading config: %w", err)
	}

	// Settings that require restart — warn and skip.
	if newCfg.HTTPSPort != d.cfg.HTTPSPort {
		d.log.Warn("https_port change requires restart")
	}
	if newCfg.DNSPort != d.cfg.DNSPort {
		d.log.Warn("dns_port change requires restart")
	}
	if newCfg.API.SecretHostname != d.cfg.API.SecretHostname {
		d.log.Warn("api.secret_hostname change requires restart")
	}

	d.cfg = newCfg
	d.log.Info("config reloaded")
	return nil
}
