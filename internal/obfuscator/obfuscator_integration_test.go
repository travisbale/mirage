//go:build integration

package obfuscator

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
)

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

func newTestAllocator(t *testing.T) context.Context {
	t.Helper()
	chromiumPath := findChromium(t)
	opts := []chromedp.ExecAllocatorOption{
		chromedp.ExecPath(chromiumPath),
		chromedp.Headless,
		chromedp.NoFirstRun,
		chromedp.NoDefaultBrowserCheck,
		chromedp.DisableGPU,
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
	}
	allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), opts...)
	t.Cleanup(allocCancel)
	return allocCtx
}

// TestNodeObfuscator_ExecutionInBrowser verifies that obfuscated JavaScript
// produces the same result as the original when executed in a real browser.
// This catches bugs where obfuscation transforms break runtime semantics
// despite producing syntactically valid JS.
func TestNodeObfuscator_ExecutionInBrowser(t *testing.T) {
	obfuscator := newTestNodeObfuscator(t)
	allocCtx := newTestAllocator(t)

	// Original JS sets a global variable to a known value.
	originalJS := `window.__test_result = (function() {
		var sum = 0;
		for (var i = 1; i <= 10; i++) { sum += i; }
		return sum;
	})();`

	obfuscatedJS, err := obfuscator.obfuscateJS(context.Background(), originalJS)
	if err != nil {
		t.Fatalf("obfuscateJS: %v", err)
	}
	if obfuscatedJS == originalJS {
		t.Fatal("obfuscated JS should differ from original")
	}

	// Serve pages: one with original JS, one with obfuscated JS.
	servePage := func(js string) *httptest.Server {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<!DOCTYPE html><html><head><script>%s</script></head>`+
				`<body><p>test</p></body></html>`, js)
		}))
		t.Cleanup(srv.Close)
		return srv
	}

	originalSrv := servePage(originalJS)
	obfuscatedSrv := servePage(obfuscatedJS)

	// Evaluate both in separate browser tabs.
	readResult := func(pageURL string) (float64, error) {
		browserCtx, browserCancel := chromedp.NewContext(allocCtx)
		defer browserCancel()

		tabCtx, timeoutCancel := context.WithTimeout(browserCtx, 15*time.Second)
		defer timeoutCancel()

		var result float64
		err := chromedp.Run(tabCtx,
			chromedp.Navigate(pageURL),
			chromedp.WaitReady("body"),
			chromedp.Evaluate(`window.__test_result`, &result),
		)
		return result, err
	}

	originalResult, err := readResult(originalSrv.URL)
	if err != nil {
		t.Fatalf("original page: %v", err)
	}

	obfuscatedResult, err := readResult(obfuscatedSrv.URL)
	if err != nil {
		t.Fatalf("obfuscated page: %v", err)
	}

	if originalResult != 55 {
		t.Errorf("original JS: expected 55, got %v", originalResult)
	}
	if obfuscatedResult != originalResult {
		t.Errorf("obfuscated JS produced %v, want %v (same as original)", obfuscatedResult, originalResult)
	}
}

// TestNodeObfuscator_MarkedHTMLExecutionInBrowser tests the full pipeline:
// HTML with marked script blocks → obfuscate → load in browser → verify
// both injected and third-party scripts execute correctly.
func TestNodeObfuscator_MarkedHTMLExecutionInBrowser(t *testing.T) {
	obfuscator := newTestNodeObfuscator(t)
	allocCtx := newTestAllocator(t)

	// HTML with a marked (injected) block and an unmarked (third-party) block.
	html := fmt.Sprintf(`<!DOCTYPE html><html><head>
<script>window.__third_party = "original";</script>
<script>%swindow.__injected = 42;%s</script>
</head><body><p>test</p></body></html>`, MarkerStart, MarkerEnd)

	obfuscatedHTML, err := obfuscator.Obfuscate(context.Background(), []byte(html))
	if err != nil {
		t.Fatalf("Obfuscate: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write(obfuscatedHTML)
	}))
	t.Cleanup(srv.Close)

	browserCtx, browserCancel := chromedp.NewContext(allocCtx)
	defer browserCancel()

	tabCtx, timeoutCancel := context.WithTimeout(browserCtx, 15*time.Second)
	defer timeoutCancel()

	var thirdParty string
	var injected float64
	err = chromedp.Run(tabCtx,
		chromedp.Navigate(srv.URL),
		chromedp.WaitReady("body"),
		chromedp.Evaluate(`window.__third_party`, &thirdParty),
		chromedp.Evaluate(`window.__injected`, &injected),
	)
	if err != nil {
		t.Fatalf("chromedp.Run: %v", err)
	}

	if thirdParty != "original" {
		t.Errorf("third-party script: got %q, want %q", thirdParty, "original")
	}
	if injected != 42 {
		t.Errorf("injected script: got %v, want 42", injected)
	}
}
