# HARDENING.md

Tracking known hardening and test coverage gaps. Ordered by priority within each section.

---

## Hardening

### ~~H1 — Unbounded body reads~~ (removed)

Not applicable in practice. Response handlers already filter to mutable MIME types (HTML, CSS, JS), which excludes large binary responses. Phishlet targets are known login pages that are never large. Revisit only if observed as a real problem in production.

---

### ~~H2 — Missing TLS listener timeouts~~ (removed)

Same reasoning as H1. A deliberate slowloris against a phishing server is a network/firewall concern, not an application one. The traffic profile is narrow and known. Revisit only if observed as a real problem in production.

---

### H3 — Silently swallowed session update errors

Both `CredentialExtractor` and `TokenExtractor` discard the error from `Store.UpdateSession`. If the write fails, captured credentials or session tokens are lost with no indication.

Affected files:
- `internal/proxy/handlers/request/credential_extractor.go`
- `internal/proxy/handlers/response/token_extractor.go`

Fix: log the error at `Warn` level (propagating it would short-circuit the pipeline, which is worse than continuing with a log).

---

### H4 — Silently swallowed store (un)marshal errors

The SQLite session store discards JSON marshal/unmarshal errors for several fields (`Custom`, `CookieTokens`, `BodyTokens`, `HTTPTokens`). A corrupted row produces an empty map with no warning.

Affected file: `internal/store/sqlite/sessions.go`

Fix: log a `Warn` when unmarshal fails (include the session ID). For marshal failures on write, return the error.

---

### H5 — API input validation gaps

Several API endpoints accept input without adequate validation:

- `sessions.go` — RFC3339 time parse errors on `since`/`until` query params are silently ignored; no pagination bounds on `limit`/`offset`
- `lures.go` — `redirect_url` and `spoof_url` are not parsed/validated as URLs; `base_domain` format not checked
- `sessions.go` — `phishlet` query param accepts arbitrary strings with no sanitisation

Affected file: `internal/api/sessions.go`, `internal/api/lures.go`

Fix: return `400 Bad Request` on parse/validation failure; add max bounds for pagination (e.g. limit ≤ 1000).

---

### H6 — WebSocket session ID not validated

After trimming the `/ws/` prefix from the URL path, the remaining session ID is not checked for emptiness before being passed to `WSHub.HandleUpgrade`.

Affected file: `internal/proxy/proxy.go`

Fix: return early if the trimmed session ID is empty.

---

## Test Coverage

### T1 — Request pipeline handlers

13 handler files, one minimal smoke-test file. These are the core of the attack pipeline.

Priority cases:
- `CredentialExtractor` — POST form, JSON body, malformed body, no matching rule
- `IPExtractor` — `X-Forwarded-For`, `CF-Connecting-IP`, direct connection
- `BlacklistChecker` — blocked IP short-circuits; whitelisted IP passes through
- `LureValidator` — valid lure, expired lure, no session cookie
- `URLRewriter` — host/path rewriting, unresolvable host
- `SessionResolver` — existing session from cookie, new session created, no phishlet

Affected file: `internal/proxy/handlers/request/handlers_request_test.go`

---

### T2 — Response pipeline handlers

10 handler files. Token and cookie extraction have no test coverage.

Priority cases:
- `TokenExtractor` — cookie token matched, HTTP header token matched, session completed, whitelist bypass
- `CookieRewriter` — domain rewritten, `__ss` session cookie injected on new session, `Secure`/`SameSite` attributes preserved
- `JSInjector` — `</body>` absent, multiple `</body>` tags, no session (already partially covered)

Affected file: `internal/proxy/handlers/response/handlers_response_test.go`

---

### T3 — SQLite session store

Session persistence has almost no test coverage. A corrupted or missing session is the most common production failure mode.

Priority cases:
- `CreateSession` / `GetSession` round-trip
- `UpdateSession` with all token types populated
- `GetSession` for unknown ID returns typed not-found error
- `ListSessions` with filters

Affected file: `internal/store/sqlite/` — needs a test file using an in-memory SQLite DB.

---

### T4 — API handlers

12 handler files, only `auth_test.go` and `ca_test.go` exist.

Priority cases:
- `sessions.go` — list with filters, get by ID, `since`/`until` boundary behaviour
- `lures.go` — create with valid/invalid input, update, delete
- `phishlets.go` — enable/disable, config update
- `blacklist.go` — add/remove IP and CIDR

Affected directory: `internal/api/`

---

### T5 — Phishlet loader edge cases

The loader is tested for the happy path but not for:
- Template parameter substitution failures
- Duplicate proxy host definitions
- Invalid regex in `sub_filters` or `credentials`
- YAML with missing required fields

Affected file: `internal/phishlet/loader_test.go`
