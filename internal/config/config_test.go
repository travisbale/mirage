package config_test

import (
	"strings"
	"testing"

	"github.com/travisbale/mirage/internal/config"
)

func TestLoad_ValidMinimal(t *testing.T) {
	cfg, err := config.Load("testdata/valid_minimal.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Domain != "phish.example.com" {
		t.Errorf("domain: got %q, want %q", cfg.Domain, "phish.example.com")
	}
	if cfg.HTTPSPort != 443 {
		t.Errorf("https_port default: got %d, want 443", cfg.HTTPSPort)
	}
	if cfg.DNSPort != 53 {
		t.Errorf("dns_port default: got %d, want 53", cfg.DNSPort)
	}
}

func TestLoad_ValidFull(t *testing.T) {
	cfg, err := config.Load("testdata/valid_full.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.HTTPSPort != 8443 {
		t.Errorf("https_port: got %d, want 8443", cfg.HTTPSPort)
	}
	if len(cfg.DNSProviders) != 1 {
		t.Errorf("dns_providers: got %d, want 1", len(cfg.DNSProviders))
	}
}

func TestLoad_UnknownField(t *testing.T) {
	_, err := config.Load("testdata/invalid_unknown_field.yaml")
	if err == nil {
		t.Fatal("expected error for unknown field, got nil")
	}
}

func TestLoad_MissingFile(t *testing.T) {
	_, err := config.Load("testdata/does_not_exist.yaml")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		file    string
		wantErr string // substring expected in error; empty means no error
	}{
		{
			name: "valid minimal",
			file: "testdata/valid_minimal.yaml",
		},
		{
			name: "valid full",
			file: "testdata/valid_full.yaml",
		},
		{
			name:    "invalid IP",
			file:    "testdata/invalid_bad_ip.yaml",
			wantErr: "not a valid IP address",
		},
		{
			name:    "missing domain",
			file:    "testdata/invalid_missing_domain.yaml",
			wantErr: "domain: required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := config.Load(tt.file)
			if err != nil {
				if tt.wantErr != "" && strings.Contains(err.Error(), tt.wantErr) {
					return // load itself can surface validation-like errors (e.g. unknown fields)
				}
				t.Fatalf("Load: %v", err)
			}
			err = cfg.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("unexpected validation error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected validation error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

// validConfig returns a minimal Config that passes Validate.
func validConfig() config.Config {
	return config.Config{
		Domain:       "phish.example.com",
		ExternalIPv4: "1.2.3.4",
		HTTPSPort:    443,
		DNSPort:      53,
		SelfSigned:   true,
		API:          config.APIConfig{SecretHostname: "api.phish.example.com"},
	}
}

func TestValidate_PortBoundaries(t *testing.T) {
	tests := []struct {
		name      string
		httpPort  int
		dnsPort   int
		wantErr   bool
		errSubstr string
	}{
		{"valid ports", 443, 53, false, ""},
		{"valid high ports", 8443, 5353, false, ""},
		{"port 1 valid", 1, 1, false, ""},
		{"port 65535 valid", 65535, 65535, false, ""},
		{"https port 0", 0, 53, true, "https_port"},
		{"https port 65536", 65536, 53, true, "https_port"},
		{"dns port 0", 443, 0, true, "dns_port"},
		{"dns port negative", 443, -1, true, "dns_port"},
		{"both invalid", 0, 0, true, "https_port"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			cfg.HTTPSPort = tt.httpPort
			cfg.DNSPort = tt.dnsPort
			err := cfg.Validate()
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected validation error, got nil")
				}
				if !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.errSubstr)
				}
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidate_ACMERequiredWhenNotSelfSigned(t *testing.T) {
	cfg := validConfig()
	cfg.SelfSigned = false
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for missing ACME config")
	}
	if !strings.Contains(err.Error(), "acme.email") {
		t.Errorf("error %q should mention acme.email", err.Error())
	}
	if !strings.Contains(err.Error(), "acme.directory_url") {
		t.Errorf("error %q should mention acme.directory_url", err.Error())
	}
}

func TestValidate_MissingSecretHostname(t *testing.T) {
	cfg := validConfig()
	cfg.API.SecretHostname = ""
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for missing secret_hostname")
	}
	if !strings.Contains(err.Error(), "api.secret_hostname") {
		t.Errorf("error %q should mention api.secret_hostname", err.Error())
	}
}
