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
