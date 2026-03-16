/*
Package proxy implements the HTTPS AiTM (adversary-in-the-middle) reverse proxy.

# Connection lifecycle

Every inbound TCP connection goes through the same sequence:

 1. Wrapped in a [PeekedConn] that tees the first TLS record into a buffer, so
    the raw ClientHello bytes are available for JA4 fingerprinting before the
    handshake consumes them.

 2. TLS handshake completes. GetCertificate selects the right phishing
    certificate by SNI. mTLS (RequireAndVerifyClientCert) is applied only when
    the ClientHello SNI matches the configured secret management hostname —
    phishing victims are never prompted for a client certificate.

 3. A [aitm.ProxyContext] is allocated for the connection and threaded through
    every handler that follows.

 4. HTTP/1.1 requests are read in a keep-alive loop by serveDecrypted. Each
    request is run through the request pipeline, forwarded upstream if no
    handler short-circuits, then the response is run through the response
    pipeline before being written back to the client.

# Request pipeline

Handlers run in the order listed below. Any handler may return
[ErrShortCircuit] to halt the chain — the request is not forwarded upstream
and the handler is responsible for writing a complete response to
[aitm.ProxyContext.ResponseWriter].

 1. JA4Extractor      — parses ClientHelloBytes into a JA4 hash; sets ctx.JA4Hash
 2. BotGuardCheck     — L1 signature check; spoofs or blocks known-bad JA4 hashes
 3. IPExtractor       — resolves client IP from socket or trusted CDN headers; sets ctx.ClientIP
 4. BlacklistChecker  — spoofs blocked IPs
 5. APIRouter         — routes management-hostname requests to the REST API handler
 6. PhishletRouter    — matches hostname against active phishlets; sets ctx.Phishlet,
                        ctx.Deployment, ctx.Lure; spoofs unrecognised hostnames
 7. LureValidator     — spoofs paused lures or requests from filtered user-agents
 8. SessionResolver   — loads or creates the session from the tracking cookie;
                        sets ctx.Session, ctx.IsNewSession
 9. TelemetryScoreCheck — L2 bot score; spoofs sessions that exceed the threshold
10. URLRewriter       — rewrites Host and URL back to the real upstream domain
                        and strips the session tracking cookie before forwarding
11. CredentialExtractor — captures username/password from POST bodies matching
                          the phishlet login spec; persists and publishes an event
12. ForcePostInjector — injects or overrides POST parameters on matching paths

# Response pipeline

Response handlers run after the upstream response is received. Unlike request
handlers, a short-circuit does not prevent the response from being forwarded to
the client — it only stops subsequent handlers from running.

 1. SecurityHeaderStripper — removes CSP, HSTS, X-Frame-Options, and related
                             headers that would interfere with the proxy
 2. CookieRewriter         — rewrites upstream Set-Cookie domains to the
                             phishing domain; injects the session tracking cookie
                             on the first response
 3. SubFilterApplier       — applies the phishlet's search/replace rules to
                             rewrite domain references in response bodies
 4. TokenExtractor         — captures auth cookies and HTTP headers; marks the
                             session complete and publishes EventSessionCompleted
                             when all required tokens are captured
 5. JSInjector             — injects the telemetry collector and WebSocket
                             redirect scripts before </body> in HTML responses
 6. JSObfuscator           — passes injected script blocks through the Node.js
                             obfuscator sidecar to defeat static fingerprinting

# Post-capture redirect flow

When TokenExtractor marks a session complete it publishes
[aitm.EventSessionCompleted]. The [WSHub] subscribes to this event and fans
the redirect URL out to all WebSocket connections waiting on that session ID.
The injected redirect script in the victim's browser holds a WebSocket open to
GET /ws/{sessionID}; when the message arrives the browser navigates to the
configured redirect URL, completing the attack flow.

A fallback polling endpoint GET /t/{sessionID}/done is also available for
environments where WebSocket connections are not reliable.
*/
package proxy
