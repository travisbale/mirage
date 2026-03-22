package obfuscator

import (
	"context"
	"strings"
	"testing"
)

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
