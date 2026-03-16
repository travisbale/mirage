package test_test

import (
	"crypto/tls"
	"net/http"
	"testing"

	"github.com/travisbale/mirage/test"
)

// TestAPI_UnauthenticatedRequestRejected verifies that a TLS connection to the
// API hostname without a client certificate is rejected at the handshake level.
func TestAPI_UnauthenticatedRequestRejected(t *testing.T) {
	harness := test.NewHarness(t)

	// Client with the API hostname as SNI but no client cert.
	// The server requires a client cert for api.phish.test, so the handshake fails.
	unauthClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,            //nolint:gosec // test only
				ServerName:        "api.phish.test", // triggers mTLS requirement
			},
		},
	}

	_, err := unauthClient.Get("https://" + harness.ProxyAddr + "/api/status")
	if err == nil {
		t.Error("expected TLS handshake error for unauthenticated API request, got nil")
	}
}

// TestAPI_Status verifies that the status endpoint returns without error.
func TestAPI_Status(t *testing.T) {
	harness := test.NewHarness(t)

	status, err := harness.API.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status.Version == "" {
		t.Error("expected non-empty version in status response")
	}
}
