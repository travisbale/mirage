package proxy_test

import (
	"io"
	"log/slog"
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
	lures := &stubLureGetter{lures: map[string]*aitm.Lure{
		"lure-001": {ID: "lure-001", RedirectURL: "https://real.example.com/dashboard"},
	}}
	hub := proxy.NewWSHub(bus, &stubSessionGetter{sessions: make(map[string]*aitm.Session)}, lures, discardLogger())

	sess := &aitm.Session{ID: "ws-sess-001", LureID: "lure-001"}
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
	lures := &stubLureGetter{lures: map[string]*aitm.Lure{
		"lure-multi": {ID: "lure-multi", RedirectURL: "https://real.example.com/home"},
	}}
	hub := proxy.NewWSHub(bus, &stubSessionGetter{sessions: make(map[string]*aitm.Session)}, lures, discardLogger())

	sess := &aitm.Session{ID: "ws-multi-001", LureID: "lure-multi"}
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
	sess := &aitm.Session{ID: "already-done", LureID: "lure-done"}
	sess.Complete()
	store := &stubSessionGetter{sessions: map[string]*aitm.Session{sess.ID: sess}}
	lures := &stubLureGetter{lures: map[string]*aitm.Lure{
		"lure-done": {ID: "lure-done", RedirectURL: "https://real.example.com/home"},
	}}
	hub := proxy.NewWSHub(bus, store, lures, discardLogger())

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
	hub := proxy.NewWSHub(bus, &stubSessionGetter{sessions: make(map[string]*aitm.Session)}, &stubLureGetter{lures: make(map[string]*aitm.Lure)}, discardLogger())

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

// ---- HandleTelemetryDone ----------------------------------------------------

func TestHandleTelemetryDone_NotDone(t *testing.T) {
	store := &stubSessionGetter{sessions: map[string]*aitm.Session{
		"sid1": {ID: "sid1"},
	}}
	hub := proxy.NewWSHub(newTestEventBus(), store, &stubLureGetter{lures: make(map[string]*aitm.Lure)}, discardLogger())

	req := httptest.NewRequest(http.MethodGet, "/t/sid1/done", nil)
	rec := httptest.NewRecorder()
	hub.HandleTelemetryDone(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"done":false`) {
		t.Errorf("expected done:false in response, got: %s", body)
	}
}

func TestHandleTelemetryDone_Done(t *testing.T) {
	sess := &aitm.Session{ID: "sid2", LureID: "lure-sid2"}
	sess.Complete()
	store := &stubSessionGetter{sessions: map[string]*aitm.Session{"sid2": sess}}
	lures := &stubLureGetter{lures: map[string]*aitm.Lure{
		"lure-sid2": {ID: "lure-sid2", RedirectURL: "https://example.com/done"},
	}}
	hub := proxy.NewWSHub(newTestEventBus(), store, lures, discardLogger())

	req := httptest.NewRequest(http.MethodGet, "/t/sid2/done", nil)
	rec := httptest.NewRecorder()
	hub.HandleTelemetryDone(rec, req)

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

type stubLureGetter struct {
	lures map[string]*aitm.Lure
}

func (s *stubLureGetter) Get(id string) (*aitm.Lure, error) {
	lure, ok := s.lures[id]
	if !ok {
		return nil, io.ErrUnexpectedEOF
	}
	return lure, nil
}
