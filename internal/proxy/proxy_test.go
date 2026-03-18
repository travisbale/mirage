package proxy_test

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/proxy"
)

// ---- helpers ----------------------------------------------------------------

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newCtx() *aitm.ProxyContext {
	return &aitm.ProxyContext{RequestID: "test-req-id"}
}

// stubHandler records calls and optionally returns an error.
type stubRequestHandler struct {
	name      string
	called    bool
	returnErr error
}

func (s *stubRequestHandler) Name() string { return s.name }
func (s *stubRequestHandler) Handle(_ *aitm.ProxyContext, _ *http.Request) error {
	s.called = true
	return s.returnErr
}

type stubResponseHandler struct {
	name      string
	called    bool
	returnErr error
}

func (s *stubResponseHandler) Name() string { return s.name }
func (s *stubResponseHandler) Handle(_ *aitm.ProxyContext, _ *http.Response) error {
	s.called = true
	return s.returnErr
}

// ---- Pipeline ---------------------------------------------------------------

func TestPipeline_RunsAllHandlers(t *testing.T) {
	h1 := &stubRequestHandler{name: "h1"}
	h2 := &stubRequestHandler{name: "h2"}
	pipeline := &proxy.Pipeline{
		RequestHandlers: []proxy.RequestHandler{h1, h2},
		Logger:          discardLogger(),
	}
	req, _ := http.NewRequest(http.MethodGet, "https://example.com/", nil)
	if err := pipeline.RunRequest(newCtx(), req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !h1.called || !h2.called {
		t.Fatal("expected both handlers to be called")
	}
}

func TestPipeline_ShortCircuit_StopsEarly(t *testing.T) {
	h1 := &stubRequestHandler{name: "h1", returnErr: proxy.ErrShortCircuit}
	h2 := &stubRequestHandler{name: "h2"}
	pipeline := &proxy.Pipeline{
		RequestHandlers: []proxy.RequestHandler{h1, h2},
		Logger:          discardLogger(),
	}
	req, _ := http.NewRequest(http.MethodGet, "https://example.com/", nil)
	err := pipeline.RunRequest(newCtx(), req)
	if !errors.Is(err, proxy.ErrShortCircuit) {
		t.Fatalf("expected ErrShortCircuit, got %v", err)
	}
	if h2.called {
		t.Fatal("h2 should not have been called after short-circuit")
	}
}

func TestPipeline_ResponseHandlers_ShortCircuit(t *testing.T) {
	rh1 := &stubResponseHandler{name: "rh1", returnErr: proxy.ErrShortCircuit}
	rh2 := &stubResponseHandler{name: "rh2"}
	pipeline := &proxy.Pipeline{ResponseHandlers: []proxy.ResponseHandler{rh1, rh2}, Logger: discardLogger()}
	resp := &http.Response{Header: make(http.Header), Body: http.NoBody}
	err := pipeline.RunResponse(newCtx(), resp)
	if !errors.Is(err, proxy.ErrShortCircuit) {
		t.Fatalf("expected ErrShortCircuit, got %v", err)
	}
	if rh2.called {
		t.Fatal("rh2 should not have been called after short-circuit")
	}
}

// ---- SpoofProxy --------------------------------------------------------

func TestSpoofProxy_NoSpoofURL_ServesDefaultPage(t *testing.T) {
	sp := proxy.NewSpoofProxy("", discardLogger())
	req := httptest.NewRequest(http.MethodGet, "https://phish.example.com/", nil)
	rec := httptest.NewRecorder()
	sp.ServeHTTP(rec, req)
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

// ---- WSHub ------------------------------------------------------------------

// newWSHubServer starts an httptest.Server that upgrades every connection via hub
// for the given sessionID. Returns the server and its ws:// URL.
func newWSHubServer(t *testing.T, hub *proxy.WSHub, sessionID string) (*httptest.Server, string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hub.HandleUpgrade(w, r, sessionID)
	}))
	t.Cleanup(srv.Close)
	return srv, "ws" + strings.TrimPrefix(srv.URL, "http") + "/"
}

// publishCompletion fires EventSessionCompleted on bus for the given session.
func publishCompletion(bus *testEventBus, sess *aitm.Session) {
	bus.Publish(aitm.Event{
		Type:       aitm.EventSessionCompleted,
		OccurredAt: time.Now(),
		Payload:    sess,
	})
}

// TestWSHub_WebSocketClientReceivesRedirect verifies the full WebSocket flow:
// a real client connects, the session completes, and the client receives the
// redirect JSON message.
func TestWSHub_WebSocketClientReceivesRedirect(t *testing.T) {
	bus := newTestEventBus()
	hub := proxy.NewWSHub(bus, &stubSessionGetter{sessions: make(map[string]*aitm.Session)}, discardLogger())

	sess := &aitm.Session{ID: "ws-sess-001", RedirectURL: "https://real.example.com/dashboard"}
	sess.Complete()

	_, wsURL := newWSHubServer(t, hub, sess.ID)
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	publishCompletion(bus, sess)

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var msg struct {
		RedirectURL string `json:"redirect_url"`
	}
	if err := conn.ReadJSON(&msg); err != nil {
		t.Fatalf("ReadJSON: %v", err)
	}
	if msg.RedirectURL != "https://real.example.com/dashboard" {
		t.Errorf("redirect_url: got %q, want %q", msg.RedirectURL, "https://real.example.com/dashboard")
	}
}

// TestWSHub_MultipleWaiters verifies that when two WebSocket clients are
// waiting for the same session, both receive the redirect message.
func TestWSHub_MultipleWaiters(t *testing.T) {
	bus := newTestEventBus()
	hub := proxy.NewWSHub(bus, &stubSessionGetter{sessions: make(map[string]*aitm.Session)}, discardLogger())

	sess := &aitm.Session{ID: "ws-multi-001", RedirectURL: "https://real.example.com/home"}
	sess.Complete()

	_, wsURL := newWSHubServer(t, hub, sess.ID)

	conn1, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial conn1: %v", err)
	}
	defer conn1.Close()

	conn2, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial conn2: %v", err)
	}
	defer conn2.Close()

	publishCompletion(bus, sess)

	for i, conn := range []*websocket.Conn{conn1, conn2} {
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		var msg struct {
			RedirectURL string `json:"redirect_url"`
		}
		if err := conn.ReadJSON(&msg); err != nil {
			t.Fatalf("conn%d ReadJSON: %v", i+1, err)
		}
		if msg.RedirectURL != "https://real.example.com/home" {
			t.Errorf("conn%d redirect_url: got %q, want %q", i+1, msg.RedirectURL, "https://real.example.com/home")
		}
	}
}

// TestWSHub_AlreadyCompleteSession verifies that a WebSocket connection for an
// already-complete session receives the redirect immediately without waiting for
// an event. This covers the MFA post-auth race: the session completes while the
// MFA page is being submitted, the victim's browser navigates to the dashboard,
// and the redirect script on the dashboard page opens a fresh WebSocket — by
// which point the completion event has already been processed and the waiter
// list is empty.
func TestWSHub_AlreadyCompleteSession(t *testing.T) {
	bus := newTestEventBus()
	sess := &aitm.Session{ID: "already-done", RedirectURL: "https://real.example.com/home"}
	sess.Complete()
	store := &stubSessionGetter{sessions: map[string]*aitm.Session{sess.ID: sess}}
	hub := proxy.NewWSHub(bus, store, discardLogger())

	_, wsURL := newWSHubServer(t, hub, sess.ID)
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var msg struct {
		RedirectURL string `json:"redirect_url"`
	}
	if err := conn.ReadJSON(&msg); err != nil {
		t.Fatalf("ReadJSON: %v", err)
	}
	if msg.RedirectURL != "https://real.example.com/home" {
		t.Errorf("redirect_url: got %q, want %q", msg.RedirectURL, "https://real.example.com/home")
	}
}

// TestWSHub_UnknownSession_CleanedOnServerClose verifies that a WebSocket
// connection for a session that never completes is cleaned up when the server
// shuts down.
func TestWSHub_UnknownSession_CleanedOnServerClose(t *testing.T) {
	bus := newTestEventBus()
	hub := proxy.NewWSHub(bus, &stubSessionGetter{sessions: make(map[string]*aitm.Session)}, discardLogger())

	srv, wsURL := newWSHubServer(t, hub, "ghost-session")
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Close the server — the underlying connection drops, HandleUpgrade returns.
	srv.Close()

	// The client should see a connection close error on the next read.
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	_, _, readErr := conn.ReadMessage()
	if readErr == nil {
		t.Error("expected connection close error after server shutdown")
	}
}

// ---- PeekedConn -------------------------------------------------------------

func TestPeekedConn_CapturesClientHello(t *testing.T) {
	// Construct a minimal synthetic TLS record:
	// content_type(1) + version(2) + length(2) + body(length)
	body := []byte("fake-client-hello-data")
	record := make([]byte, 5+len(body))
	record[0] = 0x16 // TLS handshake
	record[1] = 0x03 // TLS major version
	record[2] = 0x01 // TLS minor version
	record[3] = byte(len(body) >> 8)
	record[4] = byte(len(body))
	copy(record[5:], body)

	conn := newFakeConn(record)
	peeked := proxy.NewPeekedConn(conn)

	// Read it all out.
	buf := make([]byte, len(record))
	n, _ := peeked.Read(buf)
	if n != len(record) {
		t.Fatalf("expected to read %d bytes, got %d", len(record), n)
	}

	hello := peeked.ClientHelloBytes()
	if hello == nil {
		t.Fatal("ClientHelloBytes returned nil after complete record was read")
	}
	if !bytes.Equal(hello, record) {
		t.Errorf("captured bytes do not match original record")
	}
}

func TestPeekedConn_NilBeforeComplete(t *testing.T) {
	body := []byte("partial")
	// Only send 3 bytes — not a complete record.
	conn := newFakeConn(body[:3])
	peeked := proxy.NewPeekedConn(conn)

	buf := make([]byte, 3)
	peeked.Read(buf)

	if peeked.ClientHelloBytes() != nil {
		t.Error("expected nil before complete TLS record is captured")
	}
}

// ---- HandleTelemetryDone ----------------------------------------------------

func TestHandleTelemetryDone_NotDone(t *testing.T) {
	store := &stubSessionGetter{sessions: map[string]*aitm.Session{
		"sid1": {ID: "sid1"},
	}}
	handler := proxy.HandleTelemetryDone(store)

	req := httptest.NewRequest(http.MethodGet, "/t/sid1/done", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"done":false`) {
		t.Errorf("expected done:false in response, got: %s", body)
	}
}

func TestHandleTelemetryDone_Done(t *testing.T) {
	sess := &aitm.Session{ID: "sid2", RedirectURL: "https://example.com/done"}
	sess.Complete()
	store := &stubSessionGetter{sessions: map[string]*aitm.Session{"sid2": sess}}
	handler := proxy.HandleTelemetryDone(store)

	req := httptest.NewRequest(http.MethodGet, "/t/sid2/done", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, "https://example.com/done") {
		t.Errorf("expected redirect_url in response, got: %s", body)
	}
}

// ---- stubs ------------------------------------------------------------------

// testEventBus is an in-memory EventBus for tests.
type testEventBus struct {
	mu   sync.Mutex
	subs map[aitm.EventType][]chan aitm.Event
}

func newTestEventBus() *testEventBus {
	return &testEventBus{subs: make(map[aitm.EventType][]chan aitm.Event)}
}

func (b *testEventBus) Publish(event aitm.Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, ch := range b.subs[event.Type] {
		select {
		case ch <- event:
		default:
		}
	}
}

func (b *testEventBus) Subscribe(eventType aitm.EventType) <-chan aitm.Event {
	ch := make(chan aitm.Event, 8)
	b.mu.Lock()
	b.subs[eventType] = append(b.subs[eventType], ch)
	b.mu.Unlock()
	return ch
}

func (b *testEventBus) Unsubscribe(eventType aitm.EventType, ch <-chan aitm.Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	list := b.subs[eventType]
	for i, c := range list {
		if c == ch {
			b.subs[eventType] = append(list[:i], list[i+1:]...)
			return
		}
	}
}

type stubSessionGetter struct {
	sessions map[string]*aitm.Session
}

func (s *stubSessionGetter) Get(id string) (*aitm.Session, error) {
	sess, ok := s.sessions[id]
	if !ok {
		return nil, io.ErrUnexpectedEOF
	}
	return sess, nil
}

// fakeConn is a minimal net.Conn backed by a bytes.Reader.
type fakeConn struct {
	r *bytes.Reader
}

func newFakeConn(data []byte) *fakeConn {
	return &fakeConn{r: bytes.NewReader(data)}
}

func (c *fakeConn) Read(b []byte) (int, error)         { return c.r.Read(b) }
func (c *fakeConn) Write(b []byte) (int, error)        { return len(b), nil }
func (c *fakeConn) Close() error                       { return nil }
func (c *fakeConn) LocalAddr() net.Addr                { return dummyAddr{} }
func (c *fakeConn) RemoteAddr() net.Addr               { return dummyAddr{} }
func (c *fakeConn) SetDeadline(_ time.Time) error      { return nil }
func (c *fakeConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *fakeConn) SetWriteDeadline(_ time.Time) error { return nil }

type dummyAddr struct{}

func (dummyAddr) Network() string { return "tcp" }
func (dummyAddr) String() string  { return "127.0.0.1:0" }
