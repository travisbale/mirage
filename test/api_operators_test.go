package test_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/travisbale/mirage/sdk"
	"github.com/travisbale/mirage/test"
)

// TestAPI_OperatorInviteAndEnroll tests the full invite → enroll → list flow.
func TestAPI_OperatorInviteAndEnroll(t *testing.T) {
	harness := test.NewHarness(t)

	// 1. Invite a new operator.
	invite, err := harness.API.InviteOperator(sdk.InviteOperatorRequest{Name: "alice"})
	if err != nil {
		t.Fatalf("InviteOperator: %v", err)
	}
	if invite.Token == "" {
		t.Fatal("expected non-empty invite token")
	}

	// 2. Enroll using the token — simulate what `mirage enroll` does.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "pending-enrollment"},
	}, key)
	if err != nil {
		t.Fatalf("creating CSR: %v", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	enrollReq := sdk.EnrollRequest{
		Token:  invite.Token,
		CSRPEM: string(csrPEM),
	}
	body, _ := json.Marshal(enrollReq)

	// The enroll endpoint is unauthenticated — use a plain HTTPS client.
	enrollClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName:         "api.phish.test",
				InsecureSkipVerify: true, //nolint:gosec // test only
			},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, harness.ProxyAddr)
			},
		},
	}

	enrollURL := "https://api.phish.test" + sdk.RouteEnroll
	resp, err := enrollClient.Post(enrollURL, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("enroll request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("enroll status = %d, want 200", resp.StatusCode)
	}

	var enrollResp sdk.EnrollResponse
	if err := json.NewDecoder(resp.Body).Decode(&enrollResp); err != nil {
		t.Fatalf("decoding enroll response: %v", err)
	}
	if enrollResp.CertPEM == "" {
		t.Fatal("expected non-empty cert PEM")
	}
	if enrollResp.CACertPEM == "" {
		t.Fatal("expected non-empty CA cert PEM")
	}

	// 3. Verify the cert has the correct CN (alice, not pending-enrollment).
	block, _ := pem.Decode([]byte(enrollResp.CertPEM))
	if block == nil {
		t.Fatal("failed to decode cert PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parsing cert: %v", err)
	}
	if cert.Subject.CommonName != "alice" {
		t.Errorf("cert CN = %q, want %q", cert.Subject.CommonName, "alice")
	}

	// 4. Verify alice appears in the operators list.
	operators, err := harness.API.ListOperators()
	if err != nil {
		t.Fatalf("ListOperators: %v", err)
	}
	found := false
	for _, op := range operators.Operators {
		if op.Name == "alice" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected alice in operators list")
	}

	// 5. Reusing the token should fail.
	resp2, err := enrollClient.Post(enrollURL, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("reuse request: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode == http.StatusOK {
		t.Error("expected reused token to fail, got 200")
	}
}

// TestAPI_OperatorDelete tests inviting then removing an operator.
func TestAPI_OperatorDelete(t *testing.T) {
	harness := test.NewHarness(t)

	// Invite creates the operator name reservation. Enroll would register it,
	// but for this test we just need a registered operator to delete.
	// Use the full invite+enroll flow from TestAPI_OperatorInviteAndEnroll
	// to create "bob", then delete.
	invite, err := harness.API.InviteOperator(sdk.InviteOperatorRequest{Name: "bob"})
	if err != nil {
		t.Fatalf("InviteOperator: %v", err)
	}

	// Enroll bob.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "pending"},
	}, key)
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	enrollReq := sdk.EnrollRequest{Token: invite.Token, CSRPEM: string(csrPEM)}
	body, _ := json.Marshal(enrollReq)

	enrollClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName:         "api.phish.test",
				InsecureSkipVerify: true, //nolint:gosec
			},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, harness.ProxyAddr)
			},
		},
	}
	resp, err := enrollClient.Post("https://api.phish.test"+sdk.RouteEnroll, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	resp.Body.Close()

	// Delete bob.
	if err := harness.API.DeleteOperator("bob"); err != nil {
		t.Fatalf("DeleteOperator: %v", err)
	}

	operators, err := harness.API.ListOperators()
	if err != nil {
		t.Fatalf("ListOperators: %v", err)
	}
	for _, op := range operators.Operators {
		if op.Name == "bob" {
			t.Error("expected bob to be removed")
		}
	}
}
