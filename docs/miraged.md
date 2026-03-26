# miraged

The Mirage daemon. Runs on the phishing server and handles all traffic interception, session capture, and management API requests.

## Usage

```txt
miraged [--config <path>] [--debug]
miraged <command>
```

### Global flags

| Flag | Default | Description |
|------|---------|-------------|
| `--config` | `/etc/mirage/miraged.yaml` | Path to the YAML config file |
| `--debug` | false | Enable debug-level logging |

### Subcommands

| Command | Description |
|---------|-------------|
| `serve` | Start the daemon (default when no subcommand is given) |
| `validate` | Validate the config file and exit |
| `version` | Print the version and exit |

## What it does

On startup, `miraged` initializes these subsystems:

1. **SQLite store** — sessions, lures, and phishlet configs persist in `data_dir/data.db`
2. **Phishlet loader** — reads YAML phishlet definitions from `phishlets_dir`
3. **DNS server** — authoritative nameserver that answers A queries for phishing domains with `external_ipv4`
4. **Certificate manager** — provisions TLS certificates via ACME (Let's Encrypt) or a locally generated CA when `self_signed: true`
5. **Proxy pipeline** — MITM reverse proxy that intercepts victim HTTPS traffic, rewrites responses, captures credentials and auth tokens
6. **BotGuard** — computes JA4 TLS fingerprints and scores requests against a signature database; suspicious clients are spoofed
7. **Puppet service** (optional) — headless Chromium visits the real target site and collects browser telemetry; injects JS overrides into proxied responses so victim sessions match a legitimate visit's fingerprint
8. **JS obfuscator** (optional) — Node.js sidecar that transforms injected JavaScript on every request to defeat static fingerprinting
9. **Notification service** — delivers event notifications to webhook and Slack channels configured via the API
10. **Management API** — REST API served on `api.secret_hostname`, authenticated via mutual TLS

## Proxy architecture

Each victim's TLS connection is represented by an unexported `connection` struct that holds all connection-level state (JA4 hash, client IP, phishlet, lure, session). The `serve()` loop reads HTTP requests and routes them: WebSocket upgrades, telemetry POSTs, CORS preflights, and API requests are handled directly; all other requests go through `initSession()` (first request only) and `handleRequest()`. All response writing is centralized in `handleRequest`.

### Connection setup (`initSession`)

Runs once on the first HTTP request. Spoofs or blocks the connection if any check fails.

1. Compute JA4 hash from ClientHello bytes
2. Extract client IP from socket or trusted CDN headers
3. Bot guard check (L1) — spoof/block known-bad JA4 signatures
4. Blacklist check — spoof blocked IPs
5. Resolve phishlet and lure from hostname
6. Validate lure (not paused, UA filter matches) — spoof if invalid
7. Load existing session from `__ss` cookie, or create new session
8. Look up puppet override for the phishlet

### Per-request handling (`handleRequest`)

Methods run in order. Handler methods only make decisions or mutate the request/response — `handleRequest` centralizes all writing.

**Before forwarding upstream:**

1. Completed session redirect — 302 to lure redirect URL if session is done
2. Intercept — returns static response for paths matching intercept rules
3. Lure path rewrite — rewrites lure URL to login path on lure hits
4. Telemetry score check (L2) — spoofs sessions exceeding bot score threshold
5. URL rewrite — rewrites Host, URL, Origin, Referer to upstream domain; strips `__ss` cookie
6. Credential extraction — captures username/password from POST bodies matching login domain
7. Force POST injection — injects/overrides POST parameters on matching paths

**After receiving upstream response:**

1. Security header stripping — removes CSP, HSTS, X-Frame-Options, etc.
2. CORS header rewriting — rewrites `Access-Control-Allow-Origin` from upstream domain to phishing domain for multi-host phishlets
3. Token extraction — captures auth cookies, headers, and body tokens; marks session complete when all required tokens are captured; whitelists victim IP
4. Cookie rewriting — rewrites Set-Cookie domains to phishing domain; injects `__ss` tracking cookie on new sessions
5. Sub-filter application — applies phishlet regex rules + auto_filter to rewrite domain references in response bodies
6. JS injection — injects telemetry, redirect, puppet override, and custom scripts
7. JS obfuscation — transforms injected scripts via Node.js sidecar

## Configuration reference

See the top-level [README](../README.md#configuration) for the full config file format.
