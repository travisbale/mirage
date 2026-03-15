# miraged

The Mirage daemon. Runs on the phishing server and handles all traffic interception, session capture, and management API requests.

## Usage

```
miraged [--config <path>] [--debug] [--developer]
miraged <command>
```

### Global flags

| Flag | Default | Description |
|------|---------|-------------|
| `--config` | `/etc/mirage/miraged.yaml` | Path to the YAML config file |
| `--debug` | false | Enable debug-level logging |
| `--developer` | false | Use self-signed TLS certs instead of ACME (safe for local testing) |

### Subcommands

| Command | Description |
|---------|-------------|
| `serve` | Start the daemon (default when no subcommand is given) |
| `validate` | Validate the config file and exit |
| `version` | Print the version and exit |

## What it does

On startup, `miraged` initializes these subsystems:

1. **SQLite store** — sessions, lures, and phishlet configs persist in `db_path`
2. **Phishlet loader** — reads YAML phishlet definitions from `phishlets_dir`
3. **DNS server** — authoritative nameserver that answers A queries for phishing domains with `external_ipv4`
4. **Certificate manager** — provisions TLS certificates via ACME (Let's Encrypt) or custom certs in `--developer` mode
5. **Proxy pipeline** — MITM reverse proxy that intercepts victim HTTPS traffic, rewrites responses, captures credentials and auth tokens
6. **BotGuard** — computes JA4 TLS fingerprints and scores requests against a signature database; suspicious clients are spoofed
7. **JS obfuscator** (optional) — Node.js sidecar that transforms injected JavaScript on every request to defeat static fingerprinting
8. **Management API** — REST API served on `api.secret_hostname`, authenticated via mutual TLS

## Request pipeline

Each victim request flows through a handler chain:

**Request handlers** (in order):
1. `IPExtractor` — resolves the real client IP (honours trusted proxy headers)
2. `BlacklistCheck` — drops requests from blacklisted IPs
3. `LureRouter` — matches the request path to a configured lure
4. `LureValidator` — enforces lure pause state and UA filter rules
5. `SessionResolver` — loads an existing session from cookie or creates a new one
6. `TelemetryScoreCheck` — checks the JA4 bot score; spoofs if above threshold
7. `URLRewriter` — rewrites the request URL for upstream forwarding
8. `CredentialExtractor` — captures username/password from POST bodies matching phishlet credential rules
9. `ForcePostInjector` — injects form fields required by some phishlets

**Response handlers** (in order):
1. `SecurityHeaderStripper` — removes security headers that would break the proxy
2. `CookieRewriter` — rewrites Set-Cookie domains to the phishing domain
3. `SubFilterApplier` — runs phishlet regex substitutions on the response body
4. `TokenExtractor` — captures auth tokens from cookies and headers; marks session complete when all required tokens are present
5. `JSInjector` — injects the post-auth redirect script
6. `JSObfuscator` — obfuscates injected JS via Node.js sidecar (no-op if disabled)

## Configuration reference

See the top-level [README](../../README.md#configuration) for the full config file format.
