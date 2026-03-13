package phishlet_test

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/travisbale/mirage/aitm"
	"github.com/travisbale/mirage/events"
	"github.com/travisbale/mirage/phishlet"
)

func TestLoader(t *testing.T) {
	var loader phishlet.Loader

	tests := []struct {
		name        string
		file        string
		params      map[string]string // nil = call Load, non-nil = call LoadWithParams
		wantErr     bool
		errContains string // substring that must appear in the error string
		wantName    string // if non-empty, assert PhishletDef.Name == wantName
		assertFn    func(t *testing.T, def *aitm.PhishletDef)
	}{
		{
			name:     "valid_minimal",
			file:     "testdata/valid_minimal.yaml",
			wantErr:  false,
			wantName: "test-minimal",
			assertFn: func(t *testing.T, def *aitm.PhishletDef) {
				if len(def.ProxyHosts) != 1 {
					t.Errorf("expected 1 proxy host, got %d", len(def.ProxyHosts))
				}
				if len(def.AuthTokens) != 1 {
					t.Errorf("expected 1 auth token, got %d", len(def.AuthTokens))
				}
			},
		},
		{
			name:     "valid_full",
			file:     "testdata/valid_full.yaml",
			wantErr:  false,
			wantName: "test-full",
			assertFn: func(t *testing.T, def *aitm.PhishletDef) {
				if len(def.ProxyHosts) != 2 {
					t.Errorf("expected 2 proxy hosts, got %d", len(def.ProxyHosts))
				}
				if len(def.SubFilters) != 1 {
					t.Errorf("expected 1 sub filter, got %d", len(def.SubFilters))
				}
				if def.SubFilters[0].Search == nil {
					t.Error("SubFilter.Search regex must be compiled, got nil")
				}
				if def.Credentials.Username.Key == nil {
					t.Error("credentials.username.Key regex must be compiled, got nil")
				}
				if len(def.ForcePosts) != 1 {
					t.Errorf("expected 1 force_post, got %d", len(def.ForcePosts))
				}
				if len(def.Intercepts) != 1 {
					t.Errorf("expected 1 intercept, got %d", len(def.Intercepts))
				}
				if len(def.JSInjects) != 1 {
					t.Errorf("expected 1 js_inject, got %d", len(def.JSInjects))
				}
			},
		},
		{
			name:        "template_load_without_params_returns_error",
			file:        "testdata/template_phishlet.yaml",
			params:      nil, // call Load(), not LoadWithParams
			wantErr:     true,
			errContains: "template",
		},
		{
			name:     "template_with_params_substitutes_correctly",
			file:     "testdata/template_phishlet.yaml",
			params:   map[string]string{"tenant_id": "contoso", "region": "eu"},
			wantErr:  false,
			wantName: "test-template",
			assertFn: func(t *testing.T, def *aitm.PhishletDef) {
				if len(def.ProxyHosts) != 1 {
					t.Fatalf("expected 1 proxy host, got %d", len(def.ProxyHosts))
				}
				ph := def.ProxyHosts[0]
				if ph.PhishSubdomain != "login-eu" {
					t.Errorf("PhishSubdomain: got %q, want %q", ph.PhishSubdomain, "login-eu")
				}
				if ph.Domain != "contoso.example.com" {
					t.Errorf("Domain: got %q, want %q", ph.Domain, "contoso.example.com")
				}
				if len(def.AuthTokens) != 1 {
					t.Fatalf("expected 1 auth token, got %d", len(def.AuthTokens))
				}
				if def.AuthTokens[0].Domain != ".contoso.example.com" {
					t.Errorf("AuthToken.Domain: got %q, want %q",
						def.AuthTokens[0].Domain, ".contoso.example.com")
				}
			},
		},
		{
			name:        "template_with_missing_params_returns_error",
			file:        "testdata/template_phishlet.yaml",
			params:      map[string]string{"tenant_id": "contoso"}, // missing "region"
			wantErr:     true,
			errContains: "region",
		},
		{
			name:        "missing_required_fields",
			file:        "testdata/missing_required.yaml",
			wantErr:     true,
			errContains: "name",
		},
		{
			name:        "bad_regex_returns_field_path_error",
			file:        "testdata/bad_regex.yaml",
			wantErr:     true,
			errContains: "sub_filters[0].search",
		},
		{
			name:        "unknown_yaml_field_returns_error",
			file:        "testdata/unknown_field.yaml",
			wantErr:     true,
			errContains: "yaml",
		},
		{
			name:    "file_not_found",
			file:    "testdata/does_not_exist.yaml",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var (
				def *aitm.PhishletDef
				err error
			)
			if tc.params != nil {
				def, err = loader.LoadWithParams(tc.file, tc.params)
			} else {
				def, err = loader.Load(tc.file)
			}

			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (def=%+v)", def)
				}
				if tc.errContains != "" && !strings.Contains(err.Error(), tc.errContains) {
					t.Errorf("error %q does not contain %q", err.Error(), tc.errContains)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if def == nil {
				t.Fatal("def is nil with no error")
			}
			if tc.wantName != "" && def.Name != tc.wantName {
				t.Errorf("Name: got %q, want %q", def.Name, tc.wantName)
			}
			if tc.assertFn != nil {
				tc.assertFn(t, def)
			}
		})
	}
}

// TestValidate_HostnameCollision verifies that PhishletDef.Validate detects
// a phish_sub collision with a currently-active phishlet.
func TestValidate_HostnameCollision(t *testing.T) {
	var loader phishlet.Loader

	def, err := loader.Load("testdata/hostname_collision.yaml")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Simulate an existing active phishlet that owns "login.attacker.com".
	active := []*aitm.PhishletConfig{
		{
			Name:       "existing",
			Hostname:   "login.attacker.com",
			BaseDomain: "attacker.com",
			Enabled:    true,
		},
	}

	collisions := phishlet.Validate(def, active, "attacker.com")
	if len(collisions) == 0 {
		t.Error("expected at least one collision, got none")
	}
	if collisions[0].ConflictingPhishlet != "existing" {
		t.Errorf("ConflictingPhishlet: got %q, want %q",
			collisions[0].ConflictingPhishlet, "existing")
	}
}

// TestValidate_NoCollisionWithSelf verifies that a phishlet does not collide
// with itself (e.g., when being re-enabled after a reload).
func TestValidate_NoCollisionWithSelf(t *testing.T) {
	var loader phishlet.Loader

	def, err := loader.Load("testdata/hostname_collision.yaml")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Simulate the same phishlet already active (updating itself).
	active := []*aitm.PhishletConfig{
		{
			Name:       "collider", // same name as the phishlet being validated
			Hostname:   "login.attacker.com",
			BaseDomain: "attacker.com",
			Enabled:    true,
		},
	}

	collisions := phishlet.Validate(def, active, "attacker.com")
	if len(collisions) != 0 {
		t.Errorf("expected no collisions with self, got %d", len(collisions))
	}
}

// TestParseError_FieldPaths verifies that errors from a bad regex include
// the full dot-separated field path in the error message.
func TestParseError_FieldPaths(t *testing.T) {
	var loader phishlet.Loader
	_, err := loader.Load("testdata/bad_regex.yaml")
	if err == nil {
		t.Fatal("expected error for bad regex")
	}

	var pe phishlet.ParseErrors
	if !errors.As(err, &pe) {
		t.Fatalf("expected ParseErrors, got %T: %v", err, err)
	}

	found := false
	for _, e := range pe {
		if strings.Contains(e.Field, "sub_filters") && strings.Contains(e.Field, "search") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("no ParseError with field path containing 'sub_filters' and 'search'; got: %v", err)
	}
}

// TestWatcher publishes EventPhishletReloaded when a YAML file is modified.
func TestWatcher(t *testing.T) {
	dir := t.TempDir()
	phishletPath := dir + "/test_watch.yaml"

	// Write a valid initial file.
	writeFile(t, phishletPath, minimalYAML("watch-initial"))

	bus := events.NewBus(8)
	ch := bus.Subscribe(aitm.EventPhishletReloaded)
	defer bus.Unsubscribe(aitm.EventPhishletReloaded, ch)

	w, err := phishlet.NewWatcher(dir, bus)
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	w.Start()
	defer w.Close()

	// Overwrite the file with a new name to trigger a Write event.
	writeFile(t, phishletPath, minimalYAML("watch-reloaded"))

	select {
	case e := <-ch:
		def, ok := e.Payload.(*aitm.PhishletDef)
		if !ok {
			t.Fatalf("payload is %T, want *aitm.PhishletDef", e.Payload)
		}
		if def.Name != "watch-reloaded" {
			t.Errorf("reloaded phishlet name: got %q, want %q", def.Name, "watch-reloaded")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for EventPhishletReloaded")
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("writeFile %q: %v", path, err)
	}
}

func minimalYAML(name string) string {
	return `name: ` + name + `
author: "@test"
version: "1"
proxy_hosts:
  - phish_sub: login
    orig_sub:  login
    domain:    example.com
    is_landing: true
auth_tokens:
  - domain: ".example.com"
    keys:
      - name: session
        required: true
`
}
