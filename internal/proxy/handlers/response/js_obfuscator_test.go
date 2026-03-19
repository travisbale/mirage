package response_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/obfuscator"
	"github.com/travisbale/mirage/internal/proxy/handlers/response"
)

type stubObfuscator struct {
	called bool
	fn     func(ctx context.Context, html []byte) ([]byte, error)
}

func (s *stubObfuscator) Obfuscate(ctx context.Context, html []byte) ([]byte, error) {
	s.called = true
	return s.fn(ctx, html)
}

func TestJSObfuscator_SkipsNonHTML(t *testing.T) {
	stub := &stubObfuscator{fn: func(_ context.Context, html []byte) ([]byte, error) {
		return html, nil
	}}
	h := &response.JSObfuscator{Obfuscator: stub, Logger: discardLogger()}
	resp := newResp(http.StatusOK, "application/json", `{"key":"value"}`)

	if err := h.Handle(&aitm.ProxyContext{}, resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stub.called {
		t.Error("obfuscator should not be called for non-HTML response")
	}
}

func TestJSObfuscator_PassesThroughUnmarkedHTML(t *testing.T) {
	stub := &stubObfuscator{fn: func(_ context.Context, html []byte) ([]byte, error) {
		return html, nil
	}}
	h := &response.JSObfuscator{Obfuscator: stub, Logger: discardLogger()}
	body := "<html><body><script>var x = 1;</script></body></html>"
	resp := newResp(http.StatusOK, "text/html", body)
	ctx := &aitm.ProxyContext{Session: &aitm.Session{ID: "s1"}}

	if err := h.Handle(ctx, resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	result, _ := io.ReadAll(resp.Body)
	if string(result) != body {
		t.Errorf("expected body unchanged for unmarked HTML\ngot: %s", result)
	}
}

func TestJSObfuscator_ObfuscatesMarkedBlock(t *testing.T) {
	const sentinel = "/* obfuscated */"
	stub := &stubObfuscator{fn: func(_ context.Context, html []byte) ([]byte, error) {
		return []byte(strings.ReplaceAll(string(html), "var injected=1;", sentinel)), nil
	}}
	h := &response.JSObfuscator{Obfuscator: stub, Logger: discardLogger()}

	marked := "<script>" + obfuscator.MarkerStart + "var injected=1;" + obfuscator.MarkerEnd + "</script>"
	body := "<html><body>" + marked + "</body></html>"
	resp := newResp(http.StatusOK, "text/html", body)
	ctx := &aitm.ProxyContext{Session: &aitm.Session{ID: "s1"}}

	if err := h.Handle(ctx, resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	result, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(result), sentinel) {
		t.Errorf("expected obfuscated sentinel in output, got: %s", result)
	}
	if strings.Contains(string(result), "var injected=1;") {
		t.Error("expected original script content to be replaced")
	}
}

func TestJSObfuscator_DegradeGracefullyOnError(t *testing.T) {
	stub := &stubObfuscator{fn: func(_ context.Context, html []byte) ([]byte, error) {
		return nil, errors.New("sidecar unavailable")
	}}
	h := &response.JSObfuscator{Obfuscator: stub, Logger: discardLogger()}

	marked := "<script>" + obfuscator.MarkerStart + "var x=1;" + obfuscator.MarkerEnd + "</script>"
	body := "<html><body>" + marked + "</body></html>"
	resp := newResp(http.StatusOK, "text/html", body)
	ctx := &aitm.ProxyContext{Session: &aitm.Session{ID: "s1"}}

	if err := h.Handle(ctx, resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	result, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(result), "var x=1;") {
		t.Errorf("expected plaintext fallback on obfuscator error, got: %s", result)
	}
}
