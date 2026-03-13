package config

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the top-level configuration for miraged.
type Config struct {
	Domain        string              `yaml:"domain"`
	ExternalIPv4  string              `yaml:"external_ipv4"`
	HTTPSPort     int                 `yaml:"https_port"`
	DNSPort       int                 `yaml:"dns_port"`
	DBPath        string              `yaml:"db_path"`
	Autocert      bool                `yaml:"autocert"`
	PhishletsDir  string              `yaml:"phishlets_dir"`
	RedirectorsDir string             `yaml:"redirectors_dir"`
	DNSProviders  []DNSProviderConfig `yaml:"dns_providers"`
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
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	cfg.applyDefaults()
	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if c.HTTPSPort == 0 {
		c.HTTPSPort = 443
	}
	if c.DNSPort == 0 {
		c.DNSPort = 53
	}
	if c.DBPath == "" {
		c.DBPath = "/var/lib/mirage/data.db"
	}
	if c.PhishletsDir == "" {
		c.PhishletsDir = "/etc/mirage/phishlets"
	}
	if c.RedirectorsDir == "" {
		c.RedirectorsDir = "/etc/mirage/redirectors"
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
