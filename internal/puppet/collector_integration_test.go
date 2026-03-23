//go:build integration

package puppet_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
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
	cfg := config.PuppetConfig{
		ChromiumPath: findChromium(t),
		UserAgent:    testUA,
		MinInstances: 1,
		MaxInstances: 1,
	}
	// Chromium startup can be slow under CI resource pressure.
	// Retry up to 3 times before giving up.
	var pool *puppet.Pool
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		pool, err = puppet.NewPool(cfg, testLogger())
		if err == nil {
			break
		}
		t.Logf("NewPool attempt %d failed: %v", attempt+1, err)
		time.Sleep(2 * time.Second)
	}
	if err != nil {
		t.Fatalf("NewPool: %v (after 3 attempts)", err)
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

// TestOverride_ExecutionInBrowser verifies that the generated override JS
// actually changes browser properties when loaded in a real page. This catches
// bugs where Object.defineProperty calls are syntactically correct but
// ineffective at runtime (e.g. wrong property descriptors, frozen objects).
func TestOverride_ExecutionInBrowser(t *testing.T) {
	pool := newTestPool(t)
	srv := startTestServer(t)
	collector := puppet.NewCollector(pool, 15*time.Second, testLogger())

	// Step 1: Collect real telemetry.
	telemetry, err := collector.CollectTelemetry(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("CollectTelemetry: %v", err)
	}

	// Step 2: Build override JS from collected telemetry.
	builder := &puppet.OverrideBuilder{}
	override := builder.BuildOverride(telemetry)
	if override == "" {
		t.Fatal("expected non-empty override")
	}

	// Step 3: Serve a page with the override injected before </head>.
	overrideSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<!DOCTYPE html><html><head><script>%s</script></head>`+
			`<body><p>override test</p></body></html>`, override)
	}))
	t.Cleanup(overrideSrv.Close)

	// Step 4: Navigate a fresh tab to the override page and read properties back.
	browserCtx, browserCancel, err := pool.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer pool.Release(browserCtx, browserCancel)

	tabCtx, tabCancel := chromedp.NewContext(browserCtx)
	defer tabCancel()

	tabCtx, timeoutCancel := context.WithTimeout(tabCtx, 15*time.Second)
	defer timeoutCancel()

	// Read back the overridden properties via JS evaluation.
	var resultStr string
	readbackScript := `(function(){
		return JSON.stringify({
			userAgent: navigator.userAgent,
			platform: navigator.platform,
			language: navigator.language,
			hardwareConcurrency: navigator.hardwareConcurrency,
			deviceMemory: navigator.deviceMemory || null,
			screenWidth: screen.width,
			screenHeight: screen.height,
			colorDepth: screen.colorDepth
		});
	})()`

	err = chromedp.Run(tabCtx,
		chromedp.Navigate(overrideSrv.URL),
		chromedp.WaitReady("body"),
		chromedp.Evaluate(readbackScript, &resultStr),
	)
	if err != nil {
		t.Fatalf("chromedp.Run: %v", err)
	}

	var readback map[string]any
	if err := json.Unmarshal([]byte(resultStr), &readback); err != nil {
		t.Fatalf("unmarshal readback: %v (raw: %s)", err, resultStr)
	}

	// Step 5: Every overridden property must match the collected telemetry.
	checks := []struct {
		telemetryKey string
		readbackKey  string
	}{
		{"userAgent", "userAgent"},
		{"platform", "platform"},
		{"language", "language"},
		{"hardwareConcurrency", "hardwareConcurrency"},
		{"screenWidth", "screenWidth"},
		{"screenHeight", "screenHeight"},
		{"colorDepth", "colorDepth"},
	}
	for _, check := range checks {
		expected, ok := telemetry[check.telemetryKey]
		if !ok {
			continue
		}
		got := readback[check.readbackKey]
		if fmt.Sprintf("%v", got) != fmt.Sprintf("%v", expected) {
			t.Errorf("%s: got %v, want %v", check.readbackKey, got, expected)
		}
	}

	// deviceMemory is optional — only check if it was collected.
	if expected, ok := telemetry["deviceMemory"]; ok && expected != nil {
		got := readback["deviceMemory"]
		if fmt.Sprintf("%v", got) != fmt.Sprintf("%v", expected) {
			t.Errorf("deviceMemory: got %v, want %v", got, expected)
		}
	}
}

// TestTelemetryScript_PostsToEndpoint verifies that the injected telemetry
// script actually executes in a real browser and POSTs telemetry data to the
// expected /t/{sessionId} endpoint. This catches issues where script injection,
// minification, or browser security policies prevent the telemetry from firing.
func TestTelemetryScript_PostsToEndpoint(t *testing.T) {
	pool := newTestPool(t)

	// Read the minified telemetry script.
	telemetryJS, err := os.ReadFile("../proxy/dist/telemetry.min.js")
	if err != nil {
		t.Fatalf("reading telemetry script: %v", err)
	}

	// postReceived is closed by the server handler when the telemetry POST arrives.
	postReceived := make(chan struct{})
	var receivedBody map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/t" {
			body, _ := io.ReadAll(r.Body)
			json.Unmarshal(body, &receivedBody)
			w.WriteHeader(http.StatusOK)
			close(postReceived)
			return
		}
		// Serve the page with injected telemetry script.
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<!DOCTYPE html><html><head></head><body>`+
			`<p>telemetry test</p><script>%s</script></body></html>`, telemetryJS)
	}))
	t.Cleanup(srv.Close)

	// Navigate a browser to the page and wait for the telemetry POST.
	browserCtx, browserCancel, err := pool.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer pool.Release(browserCtx, browserCancel)

	tabCtx, tabCancel := chromedp.NewContext(browserCtx)
	defer tabCancel()

	tabCtx, timeoutCancel := context.WithTimeout(tabCtx, 15*time.Second)
	defer timeoutCancel()

	// Navigate and wait for the telemetry POST concurrently — the script fires
	// after a 2500ms setTimeout, so we block on postReceived rather than sleeping.
	chromedpDone := make(chan error, 1)
	go func() {
		chromedpDone <- chromedp.Run(tabCtx,
			chromedp.Navigate(srv.URL),
			chromedp.WaitReady("body"),
		)
	}()

	select {
	case <-postReceived:
	case <-tabCtx.Done():
		t.Fatal("timed out waiting for telemetry POST at /t")
	}

	if err := <-chromedpDone; err != nil && tabCtx.Err() == nil {
		t.Fatalf("chromedp.Run: %v", err)
	}

	if receivedBody == nil {
		t.Fatal("telemetry POST never arrived at /t")
	}

	// Verify the POST contains expected telemetry fields.
	expectedKeys := []string{
		"screen_width",
		"screen_height",
		"language",
		"platform",
	}
	for _, key := range expectedKeys {
		if _, ok := receivedBody[key]; !ok {
			t.Errorf("missing telemetry field %q in POST body", key)
		}
	}
}
