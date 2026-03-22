/*
Package proxy implements the HTTPS AiTM (adversary-in-the-middle) reverse proxy.

# Connection lifecycle

Every inbound TCP connection goes through the same sequence:

 1. Wrapped in a [peekedConn] that tees the first TLS record into a buffer, so
    the raw ClientHello bytes are available for JA4 fingerprinting before the
    handshake consumes them.

 2. TLS handshake completes. GetCertificate selects the right phishing
    certificate by SNI. mTLS (RequireAndVerifyClientCert) is applied only when
    the ClientHello SNI matches the configured secret management hostname —
    phishing victims are never prompted for a client certificate.

 3. A connection is created via newConnection. The constructor sets up
    immutable TLS-level state (JA4 hash, TLS connection state). The initSession
    method then processes the first HTTP request to perform connection-level
    setup: IP extraction, bot detection, blacklist check, phishlet/lure
    resolution, and session creation.

 4. HTTP/1.1 requests are read in a keep-alive loop by [connection.serve]. Each
    request is handled by [connection.handleRequest], which runs the per-request
    logic, forwards to upstream, and processes the response.

# Connection setup (initSession)

These checks run once per connection during initSession:

  - JA4 hash computed from ClientHello bytes
  - Client IP extracted from socket or trusted CDN headers
  - Bot guard check (L1) — JA4 signature lookup; spoofs or blocks known bots
  - Blacklist check — spoofs blocked IPs
  - Phishlet/lure resolution from hostname
  - Lure validation (paused, UA filter)
  - Session creation or loading from tracking cookie
  - Puppet override lookup

# Per-request handling (handleRequest)

All response writing is centralized in handleRequest. Handler methods only make
decisions or mutate the request/response in place.

  - Completed session redirect — 302 to lure redirect URL if session is done
  - Intercept — returns static response for matching paths
  - Lure path rewrite — rewrites lure URL to login path
  - Telemetry score check (L2) — spoofs high-scoring sessions
  - URL rewrite — rewrites Host, URL, Origin, Referer to upstream domain
  - Credential extraction — captures username/password from POST bodies
  - Force POST injection — injects/overrides POST parameters

After forwarding upstream:

  - Security header stripping — removes CSP, HSTS, X-Frame-Options, etc.
  - Token extraction — captures auth cookies, headers, and body tokens
  - Cookie rewriting — rewrites Set-Cookie domains; injects tracking cookie
  - Sub-filter application — regex search/replace on response bodies
  - JS injection — telemetry, redirect, puppet override, and custom scripts
  - JS obfuscation — transforms injected scripts via Node.js sidecar

# Post-capture redirect flow

When token extraction marks a session complete it publishes
[aitm.EventSessionCompleted]. The redirect notifier (see internal/redirect)
subscribes to this event and fans the redirect URL out to all WebSocket
connections waiting on that session ID. On the next request, handleRequest
detects the completed session and returns a 302 redirect to the lure's
redirect URL.

A fallback polling endpoint GET /t/{sessionID}/done is also available for
environments where WebSocket connections are not reliable.
*/
package proxy
