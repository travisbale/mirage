package dns_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/travisbale/mirage/internal/dns"
)

func TestGandiProvider_CreateRecord(t *testing.T) {
	var gotMethod, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	p := gandiProviderWithBaseURL(t, srv.URL)
	if err := p.CreateRecord(context.Background(), "attacker.com", "mail", "A", "1.2.3.4", 300); err != nil {
		t.Fatalf("CreateRecord: %v", err)
	}
	if gotMethod != http.MethodPut {
		t.Errorf("method: got %q, want PUT", gotMethod)
	}
	if !strings.Contains(gotPath, "attacker.com") {
		t.Errorf("path %q does not contain zone", gotPath)
	}
}

func TestGandiProvider_DeleteRecord_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	p := gandiProviderWithBaseURL(t, srv.URL)
	// 404 should be treated as success (idempotent delete)
	if err := p.DeleteRecord(context.Background(), "attacker.com", "mail", "A"); err != nil {
		t.Errorf("DeleteRecord on 404 should succeed, got: %v", err)
	}
}

func TestGandiProvider_Ping_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	p := gandiProviderWithBaseURL(t, srv.URL)
	if err := p.Ping(context.Background()); err == nil {
		t.Error("expected error for unauthorized ping")
	}
}

func gandiProviderWithBaseURL(t *testing.T, baseURL string) *dns.GandiDNSProvider {
	t.Helper()
	p, err := dns.NewGandiDNSProvider("test-key")
	if err != nil {
		t.Fatalf("NewGandiDNSProvider: %v", err)
	}
	p.SetBaseURL(baseURL)
	return p
}
