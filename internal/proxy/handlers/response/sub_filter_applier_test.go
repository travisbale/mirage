package response_test

import (
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/proxy/handlers/response"
)

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
	result, _ := io.ReadAll(resp.Body)
	if string(result) != body {
		t.Errorf("expected body unchanged for non-mutable MIME, got: %s", string(result))
	}
}

func TestSubFilterApplier_NilPhishlet_Skips(t *testing.T) {
	h := &response.SubFilterApplier{}
	body := "should not change"
	resp := newResp(http.StatusOK, "text/html", body)

	if err := h.Handle(&aitm.ProxyContext{}, resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	result, _ := io.ReadAll(resp.Body)
	if string(result) != body {
		t.Errorf("expected body unchanged when phishlet is nil, got: %s", result)
	}
}

func TestSubFilterApplier_FiltersByHostname(t *testing.T) {
	h := &response.SubFilterApplier{}
	body := `window.apiBase = "https://api.microsoft.com";`
	resp := newResp(http.StatusOK, "application/javascript", body)
	resp.Request = &http.Request{
		Host: "api.microsoft.com",
		URL:  mustURL("https://api.microsoft.com/bundle.js"),
	}

	ctx := &aitm.ProxyContext{
		Phishlet: &aitm.Phishlet{
			SubFilters: []aitm.SubFilter{
				{
					Hostname:  "api.microsoft.com",
					MimeTypes: []string{"application/javascript"},
					Search:    regexp.MustCompile(`api\.microsoft\.com`),
					Replace:   "api.phish.example.com",
				},
			},
		},
	}

	if err := h.Handle(ctx, resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	result, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(result), "api.phish.example.com") {
		t.Errorf("expected hostname rewrite, got: %s", result)
	}
}

func TestSubFilterApplier_SkipsNonMatchingHostname(t *testing.T) {
	h := &response.SubFilterApplier{}
	body := `<a href="https://login.microsoft.com/">login</a>`
	resp := newResp(http.StatusOK, "text/html", body)
	resp.Request = &http.Request{
		Host: "other.microsoft.com",
		URL:  mustURL("https://other.microsoft.com/"),
	}

	ctx := &aitm.ProxyContext{
		Phishlet: &aitm.Phishlet{
			SubFilters: []aitm.SubFilter{
				{
					Hostname:  "login.microsoft.com",
					MimeTypes: []string{"text/html"},
					Search:    regexp.MustCompile(`microsoft\.com`),
					Replace:   "phish.example.com",
				},
			},
		},
	}

	if err := h.Handle(ctx, resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	result, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(result), "phish.example.com") {
		t.Errorf("expected no rewrite for non-matching hostname, got: %s", result)
	}
}

func TestSubFilterApplier_ExpandsTemplateVariables(t *testing.T) {
	h := &response.SubFilterApplier{}
	body := `var config = { base: "PLACEHOLDER" };`
	resp := newResp(http.StatusOK, "application/javascript", body)
	resp.Request = &http.Request{
		Host: "login.microsoft.com",
		URL:  mustURL("https://login.microsoft.com/"),
	}

	ctx := &aitm.ProxyContext{
		Session: &aitm.Session{ID: "sess-template-test"},
		Phishlet: &aitm.Phishlet{
			Hostname:   "login.phish.example.com",
			BaseDomain: "phish.example.com",
			SubFilters: []aitm.SubFilter{
				{
					MimeTypes: []string{"application/javascript"},
					Search:    regexp.MustCompile(`PLACEHOLDER`),
					Replace:   "{hostname}/{domain}/{session_id}",
				},
			},
		},
	}

	if err := h.Handle(ctx, resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	result, _ := io.ReadAll(resp.Body)
	resultStr := string(result)
	if !strings.Contains(resultStr, "login.phish.example.com") {
		t.Errorf("expected {hostname} expanded, got: %s", resultStr)
	}
	if !strings.Contains(resultStr, "phish.example.com") {
		t.Errorf("expected {domain} expanded, got: %s", resultStr)
	}
	if !strings.Contains(resultStr, "sess-template-test") {
		t.Errorf("expected {session_id} expanded, got: %s", resultStr)
	}
}

func TestSubFilterApplier_MultipleFiltersAppliedInSequence(t *testing.T) {
	h := &response.SubFilterApplier{}
	body := `<script src="https://login.microsoft.com/js/app.js"></script>`
	resp := newResp(http.StatusOK, "text/html", body)
	resp.Request = &http.Request{
		Host: "login.microsoft.com",
		URL:  mustURL("https://login.microsoft.com/"),
	}

	ctx := &aitm.ProxyContext{
		Phishlet: &aitm.Phishlet{
			SubFilters: []aitm.SubFilter{
				{
					MimeTypes: []string{"text/html"},
					Search:    regexp.MustCompile(`login\.microsoft\.com`),
					Replace:   "login.phish.example.com",
				},
				{
					MimeTypes: []string{"text/html"},
					Search:    regexp.MustCompile(`/js/app\.js`),
					Replace:   "/js/app.min.js",
				},
			},
		},
	}

	if err := h.Handle(ctx, resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	result, _ := io.ReadAll(resp.Body)
	resultStr := string(result)
	if !strings.Contains(resultStr, "login.phish.example.com") {
		t.Errorf("expected first filter applied, got: %s", resultStr)
	}
	if !strings.Contains(resultStr, "/js/app.min.js") {
		t.Errorf("expected second filter applied, got: %s", resultStr)
	}
}

func TestSubFilterApplier_JavaScriptAndCSSMIME(t *testing.T) {
	h := &response.SubFilterApplier{}
	for _, mimeType := range []string{"text/javascript", "application/javascript", "text/css"} {
		body := `url("https://cdn.microsoft.com/fonts/font.woff")`
		resp := newResp(http.StatusOK, mimeType, body)
		resp.Request = &http.Request{
			Host: "login.microsoft.com",
			URL:  mustURL("https://login.microsoft.com/"),
		}

		ctx := &aitm.ProxyContext{
			Phishlet: &aitm.Phishlet{
				SubFilters: []aitm.SubFilter{
					{
						MimeTypes: []string{mimeType},
						Search:    regexp.MustCompile(`cdn\.microsoft\.com`),
						Replace:   "cdn.phish.example.com",
					},
				},
			},
		}

		if err := h.Handle(ctx, resp); err != nil {
			t.Fatalf("%s: unexpected error: %v", mimeType, err)
		}
		result, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(result), "cdn.phish.example.com") {
			t.Errorf("%s: expected rewrite, got: %s", mimeType, result)
		}
	}
}
