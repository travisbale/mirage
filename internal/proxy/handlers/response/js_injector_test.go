package response_test

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/obfuscator"
	"github.com/travisbale/mirage/internal/proxy/handlers/response"
)

func TestJSInjector_MarkersPresent(t *testing.T) {
	h := &response.JSInjector{}
	body := "<html><body><p>Hello</p></body></html>"
	resp := newResp(http.StatusOK, "text/html; charset=utf-8", body)
	resp.Request = &http.Request{
		URL: mustURL("https://login.example.com/"),
	}

	ctx := &aitm.ProxyContext{
		Session: &aitm.Session{ID: "sess-xyz"},
	}

	if err := h.Handle(ctx, resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	result, _ := io.ReadAll(resp.Body)
	bodyStr := string(result)
	if !strings.Contains(bodyStr, "__mirage_injected_start__") {
		t.Error("expected __mirage_injected_start__ marker in injected body")
	}
	if !strings.Contains(bodyStr, "__mirage_injected_end__") {
		t.Error("expected __mirage_injected_end__ marker in injected body")
	}
	if !strings.Contains(bodyStr, "sess-xyz") {
		t.Error("expected session ID to appear in injected script")
	}
}

func TestJSInjector_SkipsNonHTML(t *testing.T) {
	h := &response.JSInjector{}
	body := `{"key":"value"}`
	resp := newResp(http.StatusOK, "application/json", body)

	ctx := &aitm.ProxyContext{Session: &aitm.Session{ID: "sess-1"}}

	if err := h.Handle(ctx, resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	result, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(result), "__mirage_injected_start__") {
		t.Error("expected no injection for non-HTML response")
	}
}

func TestJSInjector_SkipsWithoutSession(t *testing.T) {
	h := &response.JSInjector{}
	body := "<html><body></body></html>"
	resp := newResp(http.StatusOK, "text/html", body)

	ctx := &aitm.ProxyContext{}

	if err := h.Handle(ctx, resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	result, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(result), "__mirage_injected_start__") {
		t.Error("expected no injection without session")
	}
}

func TestJSInjector_PuppetOverrideBeforeHead(t *testing.T) {
	h := &response.JSInjector{}
	body := "<html><head><title>Test</title></head><body></body></html>"
	resp := newResp(http.StatusOK, "text/html", body)

	ctx := &aitm.ProxyContext{
		Session:        &aitm.Session{ID: "sess-1"},
		PuppetOverride: "(function(){/*puppet*/})();",
	}

	if err := h.Handle(ctx, resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	result, _ := io.ReadAll(resp.Body)
	bodyStr := string(result)

	headIdx := strings.Index(bodyStr, "</head>")
	overrideIdx := strings.Index(bodyStr, "/*puppet*/")
	if overrideIdx == -1 {
		t.Fatal("expected puppet override in output")
	}
	if overrideIdx >= headIdx {
		t.Error("expected puppet override to appear before </head>")
	}
}

func TestJSInjector_PuppetOverrideWrappedInMarkers(t *testing.T) {
	h := &response.JSInjector{}
	body := "<html><head></head><body></body></html>"
	resp := newResp(http.StatusOK, "text/html", body)

	ctx := &aitm.ProxyContext{
		Session:        &aitm.Session{ID: "sess-1"},
		PuppetOverride: "(function(){/*puppet*/})();",
	}

	if err := h.Handle(ctx, resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	result, _ := io.ReadAll(resp.Body)
	bodyStr := string(result)

	if !strings.Contains(bodyStr, obfuscator.MarkerStart) {
		t.Error("expected obfuscator start marker around puppet override")
	}
	if !strings.Contains(bodyStr, obfuscator.MarkerEnd) {
		t.Error("expected obfuscator end marker around puppet override")
	}
}

func TestJSInjector_NoPuppetOverride_NoHeadInjection(t *testing.T) {
	h := &response.JSInjector{}
	body := "<html><head><title>Test</title></head><body></body></html>"
	resp := newResp(http.StatusOK, "text/html", body)

	ctx := &aitm.ProxyContext{
		Session: &aitm.Session{ID: "sess-1"},
	}

	if err := h.Handle(ctx, resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	result, _ := io.ReadAll(resp.Body)
	bodyStr := string(result)

	headSection := bodyStr[:strings.Index(bodyStr, "</head>")]
	if strings.Contains(headSection, "<script>") {
		t.Error("expected no script injection before </head> when no puppet override")
	}
}
