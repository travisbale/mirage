package spoof_test

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/travisbale/mirage/internal/spoof"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestServer_NoSpoofURL_ServesDefaultPage(t *testing.T) {
	sp := spoof.NewServer("", "__ss", discardLogger())
	req := httptest.NewRequest(http.MethodGet, "https://phish.example.com/", nil)
	rec := httptest.NewRecorder()
	sp.Spoof(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Errorf("expected text/html content-type, got %q", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "It works") {
		t.Errorf("expected default page body, got: %q", body)
	}
}

func TestServer_RewritesDomainsInResponse(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><a href="https://%s/login">login</a></html>`, r.Host)
	}))
	defer backend.Close()

	sp := spoof.NewServer("", "__ss", discardLogger())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "phishing.attacker.com"

	sp.SpoofTarget(rec, req, backend.URL)

	body := rec.Body.String()
	if !strings.Contains(body, "phishing.attacker.com") {
		t.Errorf("expected phishing domain in response body, got: %s", body)
	}
}

func TestServer_StripsSecurityHeaders(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	sp := spoof.NewServer("", "__ss", discardLogger())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	sp.SpoofTarget(rec, req, backend.URL)

	if rec.Header().Get("Content-Security-Policy") != "" {
		t.Errorf("expected CSP header to be stripped, got: %s", rec.Header().Get("Content-Security-Policy"))
	}
	if rec.Header().Get("Strict-Transport-Security") != "" {
		t.Errorf("expected HSTS header to be stripped, got: %s", rec.Header().Get("Strict-Transport-Security"))
	}
}

func TestServer_StripsSessionCookie(t *testing.T) {
	var receivedCookies []*http.Cookie
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedCookies = r.Cookies()
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	sp := spoof.NewServer("", "__ss", discardLogger())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "__ss", Value: "sess-123"})
	req.AddCookie(&http.Cookie{Name: "other", Value: "keep"})
	sp.SpoofTarget(rec, req, backend.URL)

	for _, cookie := range receivedCookies {
		if cookie.Name == "__ss" {
			t.Error("expected __ss cookie to be stripped from spoofed request")
		}
	}
	found := false
	for _, cookie := range receivedCookies {
		if cookie.Name == "other" {
			found = true
		}
	}
	if !found {
		t.Error("expected non-session cookies to be preserved")
	}
}
