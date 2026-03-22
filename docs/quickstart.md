# Mirage Quickstart

This guide covers running both binaries on a single machine for local testing without a real domain or ACME certificates. It uses the bundled target site — a simple login portal with MFA — so you can test the full AiTM pipeline end-to-end without hitting a real site.

## Overview

Mirage is two binaries:

- **`miraged`** — the daemon (proxy, API, DNS)
- **`mirage`** — the operator CLI (talks to miraged over mTLS)

---

## 1. Build

```bash
make build
# produces build/miraged and build/mirage
```

---

## 2. Start the target site

The `examples/target-site/` directory contains a small Flask login portal ("Vault") with email/password and MFA steps — enough to test credential capture and session token capture end-to-end.

```bash
docker compose -f examples/target-site/docker-compose.yml up -d
```

---

## 3. Create directories and config

```bash
mkdir -p /tmp/mirage/{phishlets,data}
cp examples/phishlets/form-login.yaml /tmp/mirage/phishlets/
```

Create `/tmp/mirage/miraged.yaml`:

```yaml
domain: phish.local
external_ipv4: 127.0.0.1
https_port: 8443
dns_port: 5353
data_dir: /tmp/mirage/data
phishlets_dir: /tmp/mirage/phishlets

self_signed: true

api:
  secret_hostname: api.phish.local
```

> Required fields: `domain`, `external_ipv4`, and `api.secret_hostname`. Set `self_signed: true` to skip ACME and use a locally generated CA instead. Using non-standard ports (8443/5353) avoids needing root.

---

## 4. Add /etc/hosts entries

Since there's no real DNS, point all hostnames at localhost:

```bash
echo "127.0.0.1  login.phish.local  api.phish.local  login.target.local  api.target.local" | sudo tee -a /etc/hosts
```

---

## 5. Start miraged

```bash
./build/miraged --config /tmp/mirage/miraged.yaml --debug
```

On first run it will:

- Create a TLS CA at `/tmp/mirage/data/ca/mirage-ca.crt`
- Create an mTLS API CA at `/tmp/mirage/data/api-ca.crt`
- Issue an operator client cert at `/tmp/mirage/data/operator.crt` + `operator.key`
- Load any phishlets found in `phishlets_dir`

You should see `AiTM proxy listening` in the output.

---

## 6. Trust the self-signed CA in your browser

Import `/tmp/mirage/data/ca/mirage-ca.crt` as a trusted CA so the browser doesn't block requests to the phishing hostname.

- **Firefox:** Settings → Privacy & Security → View Certificates → Authorities → Import
- **Chrome:** Settings → Privacy and security → Security → Manage certificates → Authorities → Import

---

## 7. Register the server with the CLI

In a second terminal:

```bash
./build/mirage server add \
  --alias local \
  --address https://127.0.0.1:8443 \
  --secret-hostname api.phish.local \
  --cert /tmp/mirage/data/operator.crt \
  --key /tmp/mirage/data/operator.key \
  --ca-cert /tmp/mirage/data/ca/mirage-ca.crt
```

This verifies the connection before saving. On success you'll see `Connected to miraged ... — endpoint saved as "local"`.

---

## 8. Enable the phishlet and create a lure

```bash
# Enable the phishlet on a hostname
./build/mirage phishlets enable form-login --hostname login.phish.local

# Create a lure (redirect URL is where victims land after token capture)
./build/mirage lures create form-login --redirect https://login.target.local/dashboard
```

Visit the printed lure URL in a browser that trusts the CA. You'll be taken to the standard login form. Sign in with any email and password, then enter any 6-digit code for MFA. Once MFA completes the session token is captured and the session is marked complete:

```bash
./build/mirage sessions list --completed
./build/mirage sessions show <session-id>
```

---

## File layout after first run

```txt
/tmp/mirage/
├── miraged.yaml
├── phishlets/
│   └── form-login.yaml
└── data/
    ├── data.db          # SQLite — sessions, lures, phishlet configs
    ├── ca/
    │   ├── mirage-ca.crt  # TLS CA — import into browser
    │   └── mirage-ca.key
    ├── api-ca.crt       # mTLS operator CA — used by CLI
    ├── api-ca.key
    ├── operator.crt     # operator client cert — used by CLI
    └── operator.key
```

---

## Tips

- Phishlet YAML files are hot-reloaded on save — no restart needed.
- Run `./build/miraged --config /tmp/mirage/miraged.yaml validate` to check your config without starting the daemon.
- `./build/mirage` with no subcommand drops into an interactive REPL.
- The CLI `--json` flag outputs raw JSON for scripting.

---

## Next steps

> **Note:** When a session is created, a tracking cookie (`__ss`) is set in the browser that lasts one week. If a completed session exists for that cookie, the proxy automatically redirects the victim to the real site instead of showing the login page. To test a different phishlet on the same hostname, either delete the completed session (`./build/mirage sessions delete <id>`) or use an incognito window.

- Try the API login phishlet: the target site also has a JSON-based login page at
  `/api-login`. Copy `examples/phishlets/api-login.yaml` into your phishlets
  directory, enable it, and create a lure. This phishlet captures bearer tokens
  from JSON responses instead of cookies.
- Try the multi-host phishlet: copy `examples/phishlets/multi-host.yaml` into your
  phishlets directory, enable it, and create a lure. This phishlet proxies two
  subdomains (`login` and `api`) — the login page submits credentials cross-origin
  to `api.phish.local/auth`, demonstrating multi-host routing and auto_filter
  domain rewriting.
