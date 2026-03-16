package obfuscator

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/travisbale/mirage/internal/config"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// ── NoOpObfuscator ────────────────────────────────────────────────────────────

func TestNoOpObfuscator_Obfuscate_NoChange(t *testing.T) {
	html := []byte(`<html><body><script>` + MarkerStart + `var x=1;` + MarkerEnd + `</script></body></html>`)
	got, err := (&NoOpObfuscator{}).Obfuscate(context.Background(), html)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != string(html) {
		t.Errorf("expected HTML unchanged\ngot: %s", got)
	}
}

// ── obfuscateMarkedHTML ───────────────────────────────────────────────────────

func TestObfuscateHTML_OnlyMarked(t *testing.T) {
	html := `<script>var legit = 1;</script>` +
		`<script>` + MarkerStart + `var injected=2;` + MarkerEnd + `</script>`

	var calls []string
	spy := func(_ context.Context, js string) (string, error) {
		calls = append(calls, js)
		return "/* obfuscated */" + js, nil
	}

	out, err := obfuscateMarkedHTML(context.Background(), spy, []byte(html))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(calls) != 1 {
		t.Errorf("expected 1 obfuscate call, got %d", len(calls))
	}
	if calls[0] != "var injected=2;" {
		t.Errorf("unexpected argument: %q", calls[0])
	}
	if !strings.Contains(string(out), "var legit = 1;") {
		t.Error("third-party script should be unchanged in output")
	}
}

func TestObfuscateHTML_MultipleBlocks(t *testing.T) {
	html := `<script>` + MarkerStart + `var x1=1;` + MarkerEnd + `</script>` +
		`<script>` + MarkerStart + `var x2=2;` + MarkerEnd + `</script>` +
		`<script>` + MarkerStart + `var x3=3;` + MarkerEnd + `</script>`

	var calls []string
	spy := func(_ context.Context, js string) (string, error) {
		calls = append(calls, js)
		return js, nil
	}

	if _, err := obfuscateMarkedHTML(context.Background(), spy, []byte(html)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(calls) != 3 {
		t.Errorf("expected 3 obfuscate calls, got %d", len(calls))
	}
}

func TestObfuscateHTML_NoMarker(t *testing.T) {
	html := `<html><body><script>var a = 1;</script></body></html>`

	called := false
	spy := func(_ context.Context, js string) (string, error) {
		called = true
		return js, nil
	}

	out, err := obfuscateMarkedHTML(context.Background(), spy, []byte(html))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if called {
		t.Error("obfuscate should not be called when no marker present")
	}
	if string(out) != html {
		t.Error("output should equal input when no marker present")
	}
}

// ── NodeObfuscator (requires `node` in PATH + sidecar/node_modules) ───────────

func skipIfNoNode(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not in PATH — skipping NodeObfuscator tests")
	}
	if _, err := os.Stat("sidecar/node_modules"); os.IsNotExist(err) {
		t.Skip("sidecar/node_modules not found — run `make sidecar-install`")
	}
}

func newTestNodeObfuscator(t *testing.T) *NodeObfuscator {
	t.Helper()
	skipIfNoNode(t)
	ob, err := NewNodeObfuscator(config.ObfuscatorConfig{
		SidecarDir:     "sidecar",
		MaxConcurrent:  1,
		RequestTimeout: 30 * time.Second,
	}, discardLogger())
	if err != nil {
		t.Skipf("failed to start NodeObfuscator: %v", err)
	}
	t.Cleanup(func() { ob.Shutdown(context.Background()) })
	return ob
}

func TestNodeObfuscator_DifferentOutputSameInput(t *testing.T) {
	ob := newTestNodeObfuscator(t)
	input := "function hello() { return 42; }"

	r1, err := ob.obfuscateJS(context.Background(), input)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	r2, err := ob.obfuscateJS(context.Background(), input)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if r1 == r2 {
		t.Error("expected different output on each call (random seed)")
	}
}

func TestNodeObfuscator_OutputParseable(t *testing.T) {
	ob := newTestNodeObfuscator(t)
	input := `(function() { var x = "hello world"; return x.length; })();`

	result, err := ob.obfuscateJS(context.Background(), input)
	if err != nil {
		t.Fatalf("obfuscateJS: %v", err)
	}

	// Verify output is syntactically valid JS by running it through node's VM.
	checkCmd := exec.Command("node", "-e", "var vm=require('vm');new vm.Script(process.argv[1])", result)
	if out, err := checkCmd.CombinedOutput(); err != nil {
		t.Errorf("obfuscated output is not valid JS: %v\n%s", err, out)
	}
}

func TestNodeObfuscator_Timeout(t *testing.T) {
	skipIfNoNode(t)

	ob := &NodeObfuscator{
		cfg: config.ObfuscatorConfig{
			RequestTimeout: 100 * time.Millisecond,
			MaxConcurrent:  1,
		},
		logger:   discardLogger(),
		pool:     make(chan *sidecarProcess, 1),
		shutdown: make(chan struct{}),
	}

	// Start a process that reads stdin but never writes stdout.
	hangCmd := exec.Command("/bin/sh", "-c", "cat > /dev/null")
	stdin, _ := hangCmd.StdinPipe()
	stdoutPipe, _ := hangCmd.StdoutPipe()
	if err := hangCmd.Start(); err != nil {
		t.Skipf("could not start hang process: %v", err)
	}
	t.Cleanup(func() { hangCmd.Process.Kill(); hangCmd.Wait() })

	ob.pool <- &sidecarProcess{cmd: hangCmd, stdin: stdin, stdout: bufio.NewScanner(stdoutPipe)}

	start := time.Now()
	ob.obfuscateJS(context.Background(), "var x = 1;")
	elapsed := time.Since(start)

	// Crash-recovery returns plain JS (nil error) but must respect the timeout.
	if elapsed > 500*time.Millisecond {
		t.Errorf("call took %v, expected ≤500ms (timeout is 100ms)", elapsed)
	}
}

func TestNodeObfuscator_SidecarCrashRecovery(t *testing.T) {
	ob := newTestNodeObfuscator(t)

	// Kill the sidecar directly.
	sp := <-ob.pool
	sp.cmd.Process.Kill()
	sp.cmd.Wait()
	ob.pool <- sp

	// First call after crash should degrade gracefully (plain JS, no error).
	input := "function a() { return 1; }"
	if _, err := ob.obfuscateJS(context.Background(), input); err != nil {
		t.Fatalf("unexpected error after crash: %v", err)
	}

	// Pool should now have a fresh sidecar; next call should succeed.
	result, err := ob.obfuscateJS(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error on recovery call: %v", err)
	}
	if result == "" {
		t.Error("expected non-empty result after sidecar recovery")
	}
}
