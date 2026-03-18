# Phishlet Reference

A phishlet is a YAML file that describes how to proxy and attack a specific target site. Phishlet files live in `phishlets_dir` (configured in `miraged.yaml`) and are hot-reloaded on save.

## File structure

```yaml
name:    <string>      # required
author:  <string>      # required
version: <string>      # required

proxy_hosts:  []       # required
sub_filters:  []       # optional
auth_tokens:  []       # required
credentials:  {}       # optional
login:        {}       # optional
force_post:   []       # optional
intercept:    []       # optional
js_inject:    []       # optional
```

Unknown field names are rejected with a parse error.

---

## `proxy_hosts`

Defines which upstream hosts to proxy and what phishing subdomains they map to.

```yaml
proxy_hosts:
  - phish_sub:  login          # subdomain under your phishing domain
    orig_sub:   login          # subdomain under the real target domain
    domain:     example.com    # the real target's base domain
    is_landing: true           # true on the host that receives lure traffic
    is_session: false          # true if this host sets the session cookie
    auto_filter: true          # auto-rewrite domain references in responses (default: true)
    upstream_scheme: https     # "http" or "https" (default: "https")
```

At least one entry is required. `phish_sub`, `orig_sub`, and `domain` are all required on each entry.

**How it works:** When a victim visits `login.phish.example.com`, miraged forwards the request to `login.example.com`, rewrites the response, and serves it back. All configured hosts are intercepted; all others return 404.

**`is_landing`** — exactly one host should be marked `is_landing: true`. This is where lure URLs point and where session creation begins.

**`is_session`** — mark the host that sets the primary session cookie. Used by `auth_tokens` with no explicit domain to determine where to look.

**`auto_filter`** — when `true` (the default), miraged automatically rewrites occurrences of `orig_sub.domain` to `phish_sub.phish_domain` in HTML and JavaScript responses. Disable it for hosts where auto-rewriting breaks the page and you want to rely solely on explicit `sub_filters`.

**`upstream_scheme`** — the scheme used when forwarding requests to the upstream host. Defaults to `https`. Set to `http` only for local testing targets that don't serve TLS.

---

## `sub_filters`

Regex search/replace rules applied to proxied response bodies. Used to rewrite domains, URLs, and any other content that would reveal the real site.

```yaml
sub_filters:
  - hostname:   login.example.com   # only apply to responses from this host (empty = all)
    mime_types:                      # only apply to these MIME types (empty = all)
      - text/html
      - application/javascript
    search:  "login\\.example\\.com"    # Go regex (applied to response body)
    replace: "{hostname}"               # replacement string; {hostname} = current phish hostname
```

`search` is required. Rules are applied in order; all matching rules run on every response.

**`{hostname}`** in `replace` expands to the current phishing hostname (e.g. `login.phish.example.com`).

---

## `auth_tokens`

Defines which cookies, response body values, or HTTP headers constitute a complete captured session. When all `required: true` tokens are captured, the session is marked complete and the victim is redirected.

```yaml
auth_tokens:
  - domain: ".example.com"     # cookie domain to match (leading dot = any subdomain)
    keys:
      - name:     session_token   # regex matching the cookie/header/body key name
        required: true            # session is complete when this token is captured
        http_only: false          # only capture if HttpOnly flag matches (false = either)
        always:    false          # capture on every response, not just once per session

  - type:   body                  # capture from response body (default: cookie)
    domain: login.example.com
    keys:
      - name:   access_token
        search: '"access_token"\s*:\s*"([^"]+)"'   # regex; capture group 1 is the value
        required: true

  - type:   header               # capture from response headers
    domain: login.example.com
    keys:
      - name: X-Auth-Token
        required: false
```

**`type`** — one of `cookie` (default), `body`, or `header`.

**`domain`** — for `cookie` type, matches against the cookie's domain attribute. For `body` and `header`, matches against the response's `Host`.

**`name`** — a Go regex matched against the cookie name, header name, or body key. Use `^exact_name$` for an exact match.

**`search`** — only used for `body` type. The first capture group is taken as the token value.

**`required`** — when `true`, the session is not marked complete until this token is captured. At least one required token is needed for session completion to trigger.

**`always`** — by default, a token is captured once and then skipped. Set `always: true` to re-capture on every response (useful for tokens that rotate).

---

## `credentials`

Extracts username, password, and custom fields from POST bodies or JSON payloads.

```yaml
credentials:
  username:
    key:    "^username$"    # regex matching the form field name
    search: "^(.+)$"        # regex; capture group 1 is the value
    type:   post            # "post" (form-encoded) or "json"

  password:
    key:    "^password$"
    search: "^(.+)$"
    type:   post

  custom:
    - name:   otp
      key:    "^totp$"
      search: "^(.+)$"
      type:   post
```

All fields are optional. Omit `credentials` entirely if the target uses only cookie-based auth.

**`type`** — `post` matches against `application/x-www-form-urlencoded` bodies; `json` matches against JSON request bodies.

**`custom`** — additional named fields to capture (e.g. OTP codes). Stored in the session's custom fields map under `name`.

---

## `login`

Identifies where the login form is submitted. Used to trigger credential extraction only on the right endpoint.

```yaml
login:
  domain: login.example.com
  path:   /login
```

Both fields are optional if `credentials` is omitted.

---

## `force_post`

Injects or overrides POST parameters on matching requests. Useful for targets that require specific hidden fields (e.g. `client_id`, `grant_type`) that the phished form doesn't include.

```yaml
force_post:
  - path: "/login"                    # regex matching the request path
    conditions:                       # all conditions must match (optional)
      - key:    "^client_id$"         # regex matching an existing POST param name
        search: "^.+$"                # regex matching the param value
    params:
      - key:   prompt
        value: login
      - key:   response_type
        value: code
```

`path` is required. `conditions` is optional — if omitted, the params are injected on every POST to the matching path. All conditions must be satisfied for injection to occur.

---

## `intercept`

Returns a fully custom response for matching requests. Useful for defeating bot-detection checks or feature-detection endpoints that would expose the proxy.

```yaml
intercept:
  - path:         "/api/check"           # regex matching the request path
    body_search:  '"supported"\s*:\s*true'  # optional: also match request body
    status:       200
    content_type: application/json
    body:         '{"ok":true}'
```

`path` and `status` are required. When a request matches, miraged returns the specified response immediately without forwarding to the upstream.

---

## `js_inject`

Injects a JavaScript snippet into matching pages. Primarily used for post-capture redirect logic.

```yaml
js_inject:
  - trigger_domain: login.example.com   # inject on responses from this host
    trigger_path:   "^/done$"           # optional: also match the response path (regex)
    script: |
      window.location = "https://portal.example.com";
```

`trigger_domain` and `script` are required. `trigger_path` is optional — if omitted, the script is injected on all pages from `trigger_domain`.

The script is injected as a `<script>` tag at the end of the `<body>`. If the JS obfuscator is enabled, the script is transformed on every request before injection.

---

## Validation

miraged validates phishlets on load and on file change. To check a phishlet without starting the daemon:

```bash
miraged --config /etc/mirage/miraged.yaml validate
```

Parse errors include the field path and a human-readable message:

```txt
microsoft.yaml: proxy_hosts[0].phish_sub: required
microsoft.yaml: sub_filters[1].search: invalid regex: error parsing regexp: ...
```
