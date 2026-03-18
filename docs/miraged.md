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

Each victim request flows through a handler chain:

**Request handlers** (in order):

1. `JA4Extractor` — extracts the JA4 TLS fingerprint from the ClientHello
2. `BotGuardCheck` — fast-path bot check; spoofs known bot fingerprints before session creation
3. `IPExtractor` — resolves the real client IP (honours trusted proxy headers)
4. `BlacklistChecker` — drops requests from blacklisted IPs
5. `APIRouter` — routes requests for the secret API hostname to the management API handler
6. `PhishletRouter` — matches the request hostname to an enabled phishlet; spoofs unrecognised hostnames
7. `LureValidator` — enforces lure pause state and UA filter rules
8. `SessionResolver` — loads an existing session from cookie or creates a new one
9. `PuppetOverrideResolver` — looks up cached puppet telemetry and attaches the override script to the request context
10. `TelemetryScoreCheck` — checks the JA4 bot score against the configured threshold; spoofs if above
11. `URLRewriter` — rewrites the request URL for upstream forwarding
12. `CredentialExtractor` — captures username/password from POST bodies matching phishlet credential rules
13. `ForcePostInjector` — injects form fields required by some phishlets

**Response handlers** (in order):

1. `SecurityHeaderStripper` — removes security headers that would break the proxy
2. `CookieRewriter` — rewrites Set-Cookie domains to the phishing domain
3. `SubFilterApplier` — runs phishlet regex substitutions on the response body
4. `TokenExtractor` — captures auth tokens from cookies and headers; marks session complete when all required tokens are present
5. `JSInjector` — injects the post-auth redirect script
6. `JSObfuscator` — obfuscates injected JS via Node.js sidecar (no-op if disabled)

## Configuration reference

See the top-level [README](../README.md#configuration) for the full config file format.
