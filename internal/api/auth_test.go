package api_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/api"
	"github.com/travisbale/mirage/internal/cert"
	"github.com/travisbale/mirage/sdk"
)

// ── stubs ─────────────────────────────────────────────────────────────────────

type stubSessions struct{ sessions []*aitm.Session }

func (s *stubSessions) Get(_ string) (*aitm.Session, error) { return nil, nil }
func (s *stubSessions) List(_ aitm.SessionFilter) ([]*aitm.Session, error) {
	return s.sessions, nil
}
func (s *stubSessions) Count(_ aitm.SessionFilter) (int, error)    { return len(s.sessions), nil }
func (s *stubSessions) Delete(_ string) error                      { return nil }
func (s *stubSessions) ExportCookiesJSON(_ string) ([]byte, error) { return []byte("[]"), nil }

type stubLures struct{}

func (s *stubLures) Get(_ string) (*aitm.Lure, error)                    { return nil, nil }
func (s *stubLures) Create(_ *aitm.Lure) error                           { return nil }
func (s *stubLures) Update(_ *aitm.Lure) error                           { return nil }
func (s *stubLures) Delete(_ string) error                               { return nil }
func (s *stubLures) List() ([]*aitm.Lure, error)                         { return nil, nil }
func (s *stubLures) Pause(_ string, _ time.Duration) (*aitm.Lure, error) { return nil, nil }
func (s *stubLures) Unpause(_ string) (*aitm.Lure, error)                { return nil, nil }
func (s *stubLures) URLWithParams(_ *aitm.Lure, _ int, _ map[string]string) (string, error) {
	return "", nil
}

type stubPhishlets struct{}

func (s *stubPhishlets) Push(_ string) (*aitm.Phishlet, error) { return nil, nil }
func (s *stubPhishlets) Enable(_ context.Context, _, _, _ string) (*aitm.ConfiguredPhishlet, error) {
	return nil, nil
}
func (s *stubPhishlets) Disable(_ context.Context, _ string) (*aitm.ConfiguredPhishlet, error) {
	return nil, nil
}
func (s *stubPhishlets) Get(_ string) (*aitm.PhishletConfig, error) { return nil, nil }
func (s *stubPhishlets) List() ([]*aitm.PhishletConfig, error)      { return nil, nil }

type stubBlacklist struct{}

func (s *stubBlacklist) Block(_ string)   {}
func (s *stubBlacklist) Unblock(_ string) {}
func (s *stubBlacklist) List() []string   { return nil }

type stubBotguard struct{}

func (s *stubBotguard) ListSignatures() ([]aitm.BotSignature, error) { return nil, nil }
func (s *stubBotguard) AddSignature(_ aitm.BotSignature) error       { return nil }
func (s *stubBotguard) RemoveSignature(_ string) error               { return nil }

type stubDNS struct{}

func (s *stubDNS) ListProviders() []string { return nil }

type stubBus struct{}

func (s *stubBus) Subscribe(_ sdk.EventType) <-chan aitm.Event {
	return make(chan aitm.Event)
}
func (s *stubBus) Unsubscribe(_ sdk.EventType, _ <-chan aitm.Event) {}

// ── helpers ───────────────────────────────────────────────────────────────────

func newTestRouter(sessions *stubSessions) *api.Router {
	return &api.Router{
		Sessions:  sessions,
		Lures:     &stubLures{},
		Phishlets: &stubPhishlets{},
		Blacklist: &stubBlacklist{},
		Botguard:  &stubBotguard{},
		DNS:       &stubDNS{},
		Bus:       &stubBus{},
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func newMTLSServer(t *testing.T, handler http.Handler, ca *cert.CA) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  ca.CertPool(),
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func newMTLSClient(t *testing.T, srv *httptest.Server, certPEM, keyPEM []byte) *http.Client {
	t.Helper()
	clientCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	client := srv.Client()
	client.Transport.(*http.Transport).TLSClientConfig.Certificates = []tls.Certificate{clientCert}
	return client
}

// ── auth middleware unit tests ────────────────────────────────────────────────

func TestAuthMiddleware_RejectsNilTLS(t *testing.T) {
	router := newTestRouter(&stubSessions{})

	req := httptest.NewRequest(http.MethodGet, sdk.RouteSessions, nil)
	// req.TLS is nil — simulates a plain HTTP request
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want 401", rec.Code)
	}
}

func TestAuthMiddleware_RejectsEmptyVerifiedChains(t *testing.T) {
	router := newTestRouter(&stubSessions{})

	req := httptest.NewRequest(http.MethodGet, sdk.RouteSessions, nil)
	req.TLS = &tls.ConnectionState{} // TLS established but no verified chains
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want 401", rec.Code)
	}
}

// ── mTLS round-trip ───────────────────────────────────────────────────────────

func TestMTLS_AuthenticatedRequestSucceeds(t *testing.T) {
	dir := t.TempDir()
	ca, err := cert.GenerateCA(filepath.Join(dir, "ca.crt"), "Test CA")
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	certPEM, keyPEM, err := ca.IssueClientCert("operator")
	if err != nil {
		t.Fatalf("IssueClientCert: %v", err)
	}

	sessions := &stubSessions{sessions: []*aitm.Session{
		{ID: "s1", Phishlet: "microsoft", StartedAt: time.Now()},
		{ID: "s2", Phishlet: "google", StartedAt: time.Now()},
	}}
	srv := newMTLSServer(t, newTestRouter(sessions), ca)
	client := newMTLSClient(t, srv, certPEM, keyPEM)

	resp, err := client.Get(srv.URL + sdk.RouteSessions)
	if err != nil {
		t.Fatalf("GET %s: %v", sdk.RouteSessions, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want 200", resp.StatusCode)
	}

	var body sdk.PaginatedResponse[sdk.SessionResponse]
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Total != 2 {
		t.Errorf("total: got %d, want 2", body.Total)
	}
}

func TestMTLS_WrongCAIsRejected(t *testing.T) {
	dir := t.TempDir()
	serverCA, err := cert.GenerateCA(filepath.Join(dir, "server-ca.crt"), "Test CA")
	if err != nil {
		t.Fatalf("GenerateCA (server): %v", err)
	}
	wrongCA, err := cert.GenerateCA(filepath.Join(dir, "wrong-ca.crt"), "Test CA")
	if err != nil {
		t.Fatalf("GenerateCA (wrong): %v", err)
	}

	certPEM, keyPEM, err := wrongCA.IssueClientCert("operator")
	if err != nil {
		t.Fatalf("IssueClientCert: %v", err)
	}

	srv := newMTLSServer(t, newTestRouter(&stubSessions{}), serverCA)
	client := newMTLSClient(t, srv, certPEM, keyPEM)

	// The TLS handshake itself should fail — the server rejects certs not signed by serverCA.
	_, err = client.Get(srv.URL + sdk.RouteSessions)
	if err == nil {
		t.Error("expected TLS handshake error with cert from wrong CA, got nil")
	}
}
