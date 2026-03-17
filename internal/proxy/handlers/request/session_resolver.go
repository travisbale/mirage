package request

import (
	"fmt"
	"net/http"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/proxy"
)

const sessionCookieName = "__ss"

type sessionManager interface {
	Get(id string) (*aitm.Session, error)
	NewSession(ctx *aitm.ProxyContext) (*aitm.Session, error)
}

// SessionResolver loads an existing session from the tracking cookie or creates a new one.
type SessionResolver struct {
	Sessions sessionManager
}

func (h *SessionResolver) Name() string { return "SessionResolver" }

func (h *SessionResolver) Handle(ctx *aitm.ProxyContext, req *http.Request) error {
	if cookie, err := req.Cookie(sessionCookieName); err == nil && cookie.Value != "" {
		if sess, err := h.Sessions.Get(cookie.Value); err == nil {
			ctx.Session = sess
			ctx.IsNewSession = false
			return nil
		}
	}
	sess, err := h.Sessions.NewSession(ctx)
	if err != nil {
		return fmt.Errorf("session_resolver: %w", err)
	}
	ctx.Session = sess
	ctx.IsNewSession = true
	return nil
}

var _ proxy.RequestHandler = (*SessionResolver)(nil)
