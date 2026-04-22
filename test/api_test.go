package test_test

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/travisbale/mirage/internal/cert"
	"github.com/travisbale/mirage/sdk"
	"github.com/travisbale/mirage/test"
)

// TestAPI_UnauthenticatedRequestRejected verifies that an API request without
// a client certificate receives a 401 Unauthorized response.
func TestAPI_UnauthenticatedRequestRejected(t *testing.T) {
	t.Parallel()
	harness := test.NewHarness(t)

	// Client with the API hostname as SNI but no client cert.
	unauthClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // test only
				ServerName:         "api.phish.test",
			},
		},
	}

	req, _ := http.NewRequest(http.MethodGet, "https://"+harness.ProxyAddr+"/api/status", nil)
	req.Host = "api.phish.test"
	resp, err := unauthClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

// TestAPI_Status verifies that the status endpoint returns without error.
func TestAPI_Status(t *testing.T) {
	t.Parallel()
	harness := test.NewHarness(t)

	status, err := harness.API.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status.Version == "" {
		t.Error("expected non-empty version in status response")
	}
}

// TestAPI_WrongCARejectedAtHandshake verifies that a client cert signed by an
// untrusted CA fails at the TLS handshake — not just at the app-layer auth
// check. Guards against regressions that weaken the API server's ClientAuth
// mode or its ClientCAs pool.
func TestAPI_WrongCARejectedAtHandshake(t *testing.T) {
	t.Parallel()
	harness := test.NewHarness(t)

	dir := t.TempDir()
	wrongCA, err := cert.GenerateCA(filepath.Join(dir, "wrong-ca.crt"), "Wrong CA")
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	certPEM, keyPEM, err := wrongCA.IssueClientCert("impostor")
	if err != nil {
		t.Fatalf("IssueClientCert: %v", err)
	}
	clientCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName:         "api.phish.test",
				InsecureSkipVerify: true, //nolint:gosec // test only
				// GetClientCertificate bypasses Go's CA-DN filtering and
				// forces the untrusted cert onto the wire. Using Certificates
				// would cause the client to silently omit the cert because
				// its issuer isn't in the server's CertificateRequest.
				GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
					return &clientCert, nil
				},
			},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, harness.ProxyAddr)
			},
		},
	}

	if _, err := client.Get("https://api.phish.test" + sdk.RouteStatus); err == nil {
		t.Error("expected TLS handshake error for cert from untrusted CA, got nil")
	}
}
