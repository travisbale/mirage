package redirect_test

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/events"
	"github.com/travisbale/mirage/internal/redirect"
	"github.com/travisbale/mirage/sdk"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// newTestServer starts an httptest.Server that upgrades every connection via
// the notifier for the given sessionID. Returns the server and its ws:// URL.
func newTestServer(t *testing.T, notifier *redirect.Notifier, sessionID string) (*httptest.Server, string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		notifier.WaitForRedirect(w, r, sessionID)
	}))
	t.Cleanup(srv.Close)
	return srv, "ws" + strings.TrimPrefix(srv.URL, "http") + "/"
}

func publishCompletion(bus *events.Bus, sess *aitm.Session) {
	bus.Publish(aitm.Event{
		Type:       sdk.EventSessionCompleted,
		OccurredAt: time.Now(),
		Payload:    sess,
	})
}

func TestNotifier_WebSocketClientReceivesRedirect(t *testing.T) {
	bus := events.NewBus(8)
	lures := &stubLureGetter{lures: map[string]*aitm.Lure{
		"lure-001": {ID: "lure-001", RedirectURL: "https://real.example.com/dashboard"},
	}}
	notifier := redirect.NewNotifier(bus, &stubSessionGetter{sessions: make(map[string]*aitm.Session)}, lures, discardLogger())

	sess := &aitm.Session{ID: "ws-sess-001", LureID: "lure-001"}
	sess.Complete()

	_, wsURL := newTestServer(t, notifier, sess.ID)
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

func TestNotifier_MultipleWaiters(t *testing.T) {
	bus := events.NewBus(8)
	lures := &stubLureGetter{lures: map[string]*aitm.Lure{
		"lure-multi": {ID: "lure-multi", RedirectURL: "https://real.example.com/home"},
	}}
	notifier := redirect.NewNotifier(bus, &stubSessionGetter{sessions: make(map[string]*aitm.Session)}, lures, discardLogger())

	sess := &aitm.Session{ID: "ws-multi-001", LureID: "lure-multi"}
	sess.Complete()

	_, wsURL := newTestServer(t, notifier, sess.ID)

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

func TestNotifier_AlreadyCompleteSession(t *testing.T) {
	bus := events.NewBus(8)
	sess := &aitm.Session{ID: "already-done", LureID: "lure-done"}
	sess.Complete()
	store := &stubSessionGetter{sessions: map[string]*aitm.Session{sess.ID: sess}}
	lures := &stubLureGetter{lures: map[string]*aitm.Lure{
		"lure-done": {ID: "lure-done", RedirectURL: "https://real.example.com/home"},
	}}
	notifier := redirect.NewNotifier(bus, store, lures, discardLogger())

	_, wsURL := newTestServer(t, notifier, sess.ID)
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

func TestNotifier_UnknownSession_CleanedOnServerClose(t *testing.T) {
	bus := events.NewBus(8)
	notifier := redirect.NewNotifier(bus, &stubSessionGetter{sessions: make(map[string]*aitm.Session)}, &stubLureGetter{lures: make(map[string]*aitm.Lure)}, discardLogger())

	srv, wsURL := newTestServer(t, notifier, "ghost-session")
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	srv.Close()

	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	_, _, readErr := conn.ReadMessage()
	if readErr == nil {
		t.Error("expected connection close error after server shutdown")
	}
}

func TestPollForRedirect_NotDone(t *testing.T) {
	store := &stubSessionGetter{sessions: map[string]*aitm.Session{
		"sid1": {ID: "sid1"},
	}}
	notifier := redirect.NewNotifier(events.NewBus(8), store, &stubLureGetter{lures: make(map[string]*aitm.Lure)}, discardLogger())

	rec := httptest.NewRecorder()
	notifier.PollForRedirect(rec, "sid1")

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"done":false`) {
		t.Errorf("expected done:false in response, got: %s", body)
	}
}

func TestPollForRedirect_Done(t *testing.T) {
	sess := &aitm.Session{ID: "sid2", LureID: "lure-sid2"}
	sess.Complete()
	store := &stubSessionGetter{sessions: map[string]*aitm.Session{"sid2": sess}}
	lures := &stubLureGetter{lures: map[string]*aitm.Lure{
		"lure-sid2": {ID: "lure-sid2", RedirectURL: "https://example.com/done"},
	}}
	notifier := redirect.NewNotifier(events.NewBus(8), store, lures, discardLogger())

	rec := httptest.NewRecorder()
	notifier.PollForRedirect(rec, "sid2")

	body := rec.Body.String()
	if !strings.Contains(body, "https://example.com/done") {
		t.Errorf("expected redirect_url in response, got: %s", body)
	}
}

// ---- stubs ------------------------------------------------------------------

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
