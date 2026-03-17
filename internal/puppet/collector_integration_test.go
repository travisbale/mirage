//go:build integration

package puppet_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/travisbale/mirage/internal/config"
	"github.com/travisbale/mirage/internal/puppet"
)

const testUA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

func findChromium(t *testing.T) string {
	t.Helper()
	for _, name := range []string{"chromium-browser", "chromium", "google-chrome-stable", "google-chrome"} {
		if path, err := exec.LookPath(name); err == nil {
			return path
		}
	}
	t.Skip("no chromium/chrome binary found — skipping integration test")
	return ""
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func startTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!DOCTYPE html><html><head><title>Puppet Test</title></head><body><p>test</p></body></html>`)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newTestPool(t *testing.T) *puppet.Pool {
	t.Helper()
	pool, err := puppet.NewPool(config.PuppetConfig{
		ChromiumPath: findChromium(t),
		UserAgent:    testUA,
		MinInstances: 1,
		MaxInstances: 1,
	}, testLogger())
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	t.Cleanup(func() { pool.Shutdown(context.Background()) })
	return pool
}

// TestCollector_CollectTelemetry verifies that collect.js returns all expected
// keys with correct types when run against a real Chromium instance.
func TestCollector_CollectTelemetry(t *testing.T) {
	pool := newTestPool(t)
	srv := startTestServer(t)
	collector := puppet.NewCollector(pool, 15*time.Second, testLogger())

	telemetry, err := collector.CollectTelemetry(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("CollectTelemetry: %v", err)
	}

	// Every key that collect.js returns must be present.
	requiredKeys := []string{
		"userAgent",
		"screenWidth",
		"screenHeight",
		"platform",
		"language",
		"hardwareConcurrency",
		"colorDepth",
	}
	for _, key := range requiredKeys {
		if _, ok := telemetry[key]; !ok {
			t.Errorf("missing telemetry key %q", key)
		}
	}

	// deviceMemory is optional (not supported in all environments).
	if _, ok := telemetry["deviceMemory"]; !ok {
		t.Log("deviceMemory absent (expected on some platforms)")
	}

	// Spot-check types and values.
	if ua, ok := telemetry["userAgent"].(string); !ok || ua == "" {
		t.Errorf("userAgent: want non-empty string, got %v (%T)", telemetry["userAgent"], telemetry["userAgent"])
	}
	if sw, ok := telemetry["screenWidth"].(float64); !ok || sw <= 0 {
		t.Errorf("screenWidth: want positive number, got %v", telemetry["screenWidth"])
	}
	if hc, ok := telemetry["hardwareConcurrency"].(float64); !ok || hc < 1 {
		t.Errorf("hardwareConcurrency: want >= 1, got %v", telemetry["hardwareConcurrency"])
	}

	// The configured UA should be reflected in the collected telemetry.
	if ua := telemetry["userAgent"].(string); ua != testUA {
		t.Errorf("userAgent: got %q, want %q", ua, testUA)
	}
}

// TestCollector_RoundTrip verifies the full pipeline: collect telemetry from a
// real Chromium instance, build a JS override, and confirm the output contains
// the collected values. This is the test that catches collect.js regressions.
func TestCollector_RoundTrip(t *testing.T) {
	pool := newTestPool(t)
	srv := startTestServer(t)
	collector := puppet.NewCollector(pool, 15*time.Second, testLogger())

	telemetry, err := collector.CollectTelemetry(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("CollectTelemetry: %v", err)
	}

	builder := &puppet.OverrideBuilder{}
	override := builder.BuildOverride(telemetry)

	if override == "" {
		t.Fatal("expected non-empty override from real telemetry")
	}
	if !strings.HasPrefix(override, "(function(){") {
		t.Errorf("override should be an IIFE, got: %.80s...", override)
	}

	// The override must contain the actual UA string from Chromium.
	if !strings.Contains(override, testUA) {
		t.Errorf("override should contain configured userAgent %q", testUA)
	}

	// Should contain both navigator and screen property overrides.
	for _, fragment := range []string{
		`Object.defineProperty(navigator,"userAgent"`,
		`Object.defineProperty(navigator,"platform"`,
		`Object.defineProperty(screen,"width"`,
		`Object.defineProperty(screen,"height"`,
		`Object.defineProperty(screen,"colorDepth"`,
	} {
		if !strings.Contains(override, fragment) {
			t.Errorf("override missing %s", fragment)
		}
	}
}
