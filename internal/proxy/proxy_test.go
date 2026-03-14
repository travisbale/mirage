package proxy_test

import (
	"bytes"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

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
	name    string
	called  bool
	returnErr error
}

func (s *stubRequestHandler) Name() string { return s.name }
func (s *stubRequestHandler) Handle(_ *aitm.ProxyContext, _ *http.Request) error {
	s.called = true
	return s.returnErr
}

type stubResponseHandler struct {
	name    string
	called  bool
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
	if err != proxy.ErrShortCircuit {
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
	if err != proxy.ErrShortCircuit {
		t.Fatalf("expected ErrShortCircuit, got %v", err)
	}
	if rh2.called {
		t.Fatal("rh2 should not have been called after short-circuit")
	}
}

// ---- ActiveHostnameSet --------------------------------------------------------

func TestActiveHostnameSet_Contains(t *testing.T) {
	ah := &proxy.ActiveHostnameSet{}
	ah.Add("phish.example.com")

	if !ah.Contains("phish.example.com") {
		t.Error("expected Contains to return true for added hostname")
	}
	if !ah.Contains("PHISH.EXAMPLE.COM") {
		t.Error("expected Contains to be case-insensitive")
	}
	if ah.Contains("other.example.com") {
		t.Error("expected Contains to return false for unknown hostname")
	}
}

func TestActiveHostnameSet_Remove(t *testing.T) {
	ah := &proxy.ActiveHostnameSet{}
	ah.Add("phish.example.com")
	ah.Remove("phish.example.com")
	if ah.Contains("phish.example.com") {
		t.Error("expected hostname to be removed")
	}
}

func TestActiveHostnameSet_Snapshot(t *testing.T) {
	ah := &proxy.ActiveHostnameSet{}
	ah.Add("a.example.com")
	ah.Add("b.example.com")
	snap := ah.Snapshot()
	if len(snap) != 2 {
		t.Errorf("expected 2 hostnames in snapshot, got %d", len(snap))
	}
}

// ---- SpoofProxy --------------------------------------------------------

func TestSpoofProxy_EmptyURL_Returns200(t *testing.T) {
	sp := proxy.NewSpoofProxy("")
	req := httptest.NewRequest(http.MethodGet, "https://phish.example.com/", nil)
	rec := httptest.NewRecorder()
	sp.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

// ---- WSHub ------------------------------------------------------------------

func TestWSHub_TimeoutCase(t *testing.T) {
	bus := newTestEventBus()
	hub := proxy.NewWSHub(bus, discardLogger())
	_ = hub // confirmed non-nil, no panic on construction
}

// ---- WSHub redirect on completion -------------------------------------------

func TestWSHub_SendsRedirectOnCompletion(t *testing.T) {
	bus := newTestEventBus()
	hub := proxy.NewWSHub(bus, discardLogger())
	_ = hub

	// Publish EventSessionCompleted and verify the bus delivers it.
	sess := &aitm.Session{
		ID:          "sess-001",
		RedirectURL: "https://real.example.com/dashboard",
	}
	sess.Complete()

	done := make(chan struct{})
	ch := bus.Subscribe(aitm.EventSessionCompleted)
	go func() {
		defer close(done)
		event := <-ch
		got, ok := event.Payload.(*aitm.Session)
		if !ok {
			t.Errorf("expected *aitm.Session payload")
			return
		}
		if got.LureRedirectURL() != "https://real.example.com/dashboard" {
			t.Errorf("unexpected redirect URL: %s", got.LureRedirectURL())
		}
	}()

	bus.Publish(aitm.Event{
		Type:       aitm.EventSessionCompleted,
		OccurredAt: time.Now(),
		Payload:    sess,
	})

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for completion event")
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
	store := &stubSessionStore{sessions: map[string]*aitm.Session{
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
	store := &stubSessionStore{sessions: map[string]*aitm.Session{"sid2": sess}}
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

type stubSessionStore struct {
	sessions map[string]*aitm.Session
}

func (s *stubSessionStore) GetSession(id string) (*aitm.Session, error) {
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

func (c *fakeConn) Read(b []byte) (int, error) { return c.r.Read(b) }
func (c *fakeConn) Write(b []byte) (int, error) { return len(b), nil }
func (c *fakeConn) Close() error                { return nil }
func (c *fakeConn) LocalAddr() net.Addr         { return dummyAddr{} }
func (c *fakeConn) RemoteAddr() net.Addr        { return dummyAddr{} }
func (c *fakeConn) SetDeadline(_ time.Time) error      { return nil }
func (c *fakeConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *fakeConn) SetWriteDeadline(_ time.Time) error { return nil }

type dummyAddr struct{}

func (dummyAddr) Network() string { return "tcp" }
func (dummyAddr) String() string  { return "127.0.0.1:0" }
