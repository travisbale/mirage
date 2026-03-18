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
9. **Management API** — REST API served on `api.secret_hostname`, authenticated via mutual TLS

## Request pipeline

Each victim request flows through two handler chains — one before the upstream request is made, one after the response comes back.

Handlers communicate through `ProxyContext`, a per-request struct that accumulates state as it passes through the chain. The ordering is load-bearing: later handlers depend on fields set by earlier ones. A handler that short-circuits (by returning `ErrShortCircuit`) writes a response directly and stops the chain — no upstream request is made and no response handlers run.

### Context fields and where they are set

| Field | Set by | Used by |
|-------|--------|---------|
| `JA4` | `JA4Extractor` | `BotGuardCheck`, `TelemetryScoreCheck` |
| `ClientIP` | `IPExtractor` | `BlacklistChecker`, `TokenExtractor` |
| `Phishlet` | `PhishletRouter` | `LureValidator`, `LureRedirector`, `URLRewriter`, `CredentialExtractor`, `ForcePostInjector`, `CookieRewriter`, `SubFilterApplier`, `TokenExtractor`, `JSInjector` |
| `Lure` | `PhishletRouter` | `LureValidator`, `LureRedirector` |
| `Session` | `SessionGate` | `LureRedirector`, `PuppetOverrideResolver`, `CredentialExtractor`, `CookieRewriter`, `TokenExtractor`, `JSInjector` |
| `IsNewSession` | `SessionGate` | `CookieRewriter` (injects the `__ss` tracking cookie on first response) |
| `PuppetOverride` | `PuppetOverrideResolver` | `JSInjector` |

### Request handlers (in order)

1. `JA4Extractor` — extracts the JA4 TLS fingerprint from the ClientHello; sets `ctx.JA4`
2. `BotGuardCheck` — fast-path bot check using the JA4 signature database; spoofs and short-circuits for known bots before any session state is touched
3. `IPExtractor` — resolves the real client IP, honouring trusted proxy headers; sets `ctx.ClientIP`
4. `BlacklistChecker` — spoofs and short-circuits if the client IP is blacklisted
5. `APIRouter` — short-circuits requests for the secret API hostname to the management API handler; all other requests pass through
6. `PhishletRouter` — matches the request hostname to an enabled phishlet; spoofs and short-circuits for unrecognised hostnames. Sets `ctx.Phishlet` and `ctx.Lure` (lure may be nil if no lure path matches)
7. `SessionGate` — combines session resolution with lure validation into a single step. For requests with an existing `__ss` cookie, the session is loaded and all lure checks are skipped. For new visitors (no cookie), lure rules are enforced before a session is created: no matching lure, a paused lure, or a UA filter mismatch all result in a spoof. A session is only created after lure validation passes, so no orphaned sessions accumulate for spoofed requests. Sets `ctx.Session` and `ctx.IsNewSession`.
8. `LureRedirector` — on the initial lure hit (request path matches `ctx.Lure.Path`), transparently rewrites the path to the phishlet's `login.path` so the upstream serves the login page at the lure URL
9. `PuppetOverrideResolver` — looks up cached puppet telemetry for the active phishlet and attaches the JS override script to `ctx.PuppetOverride`
10. `TelemetryScoreCheck` — scores the JA4 fingerprint for bot likelihood; spoofs and short-circuits if the score exceeds the configured threshold
11. `URLRewriter` — rewrites the request `Host` and URL to the real upstream domain; strips the `__ss` cookie so it is never forwarded to the target site
12. `CredentialExtractor` — captures username and password from POST bodies and JSON payloads matching the phishlet's credential rules; writes to `ctx.Session`
13. `ForcePostInjector` — injects or overrides POST parameters required by some phishlets before the request reaches the upstream

### Response handlers (in order)

Response handlers run on the upstream response before it is forwarded to the victim. They cannot short-circuit — all handlers always run.

1. `SecurityHeaderStripper` — removes upstream security headers (`Content-Security-Policy`, `X-Frame-Options`, etc.) that would break the proxy or expose the phishing domain to the victim's browser
2. `TokenExtractor` — captures auth tokens (cookies, headers) matching the phishlet's `auth_tokens` rules against the **original upstream domains**; marks the session complete when all required tokens are present, then whitelists the victim's IP to prevent accidental blacklisting. Must run before `CookieRewriter` so the original cookie domains are still intact.
3. `CookieRewriter` — rewrites `Set-Cookie` domains from the real upstream domain to the phishing domain so cookies are scoped correctly; injects the `__ss` session tracking cookie on new sessions (`ctx.IsNewSession`)
4. `SubFilterApplier` — runs the phishlet's regex substitution rules against the response body, rewriting upstream domain references to the phishing domain
5. `JSInjector` — injects the post-auth redirect script before `</body>` (redirects the victim after token capture); also injects the puppet override script before `</head>` if `ctx.PuppetOverride` is set
6. `JSObfuscator` — passes injected script blocks through the Node.js obfuscator sidecar to defeat static JS fingerprinting; no-op if the obfuscator is disabled

## Configuration reference

See the top-level [README](../README.md#configuration) for the full config file format.
