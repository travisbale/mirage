package request

import (
	"fmt"
	"net/http"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/proxy"
)

const sessionCookieName = "__ss"

// SessionLookup retrieves an existing session by ID.
type SessionLookup interface {
	GetSession(id string) (*aitm.Session, error)
}

// SessionFactory creates new sessions for first-time visitors.
type SessionFactory interface {
	NewSession(ctx *aitm.ProxyContext) (*aitm.Session, error)
}

// SessionResolver loads an existing session from the tracking cookie or creates a new one.
type SessionResolver struct {
	Store   SessionLookup
	Factory SessionFactory
}

func (h *SessionResolver) Name() string { return "SessionResolver" }

func (h *SessionResolver) Handle(ctx *aitm.ProxyContext, req *http.Request) error {
	if cookie, err := req.Cookie(sessionCookieName); err == nil && cookie.Value != "" {
		if sess, err := h.Store.GetSession(cookie.Value); err == nil {
			ctx.Session = sess
			ctx.IsNewSession = false
			return nil
		}
	}
	sess, err := h.Factory.NewSession(ctx)
	if err != nil {
		return fmt.Errorf("session_resolver: %w", err)
	}
	ctx.Session = sess
	ctx.IsNewSession = true
	return nil
}

var _ proxy.RequestHandler = (*SessionResolver)(nil)
