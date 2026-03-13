# Mirage

Mirage is an Adversary-in-the-Middle (AiTM) phishing framework for authorized red team engagements. It acts as a reverse proxy between the victim and a legitimate target, capturing live session cookies post-MFA to bypass two-factor authentication.

> **For authorized use only.** Mirage is a security research tool intended for penetration testing engagements with explicit written permission from the target organization.

## Architecture

Mirage is split into two binaries:

- **`miraged`** — the daemon that runs on the phishing server. Handles DNS, TLS, the reverse proxy, session capture, and bot detection.
- **`mirage`** — a thin CLI client that connects to one or more `miraged` instances over mutual TLS to manage phishlets, lures, and sessions.

The core business logic lives in the `aitm/` package. Infrastructure implementations (SQLite, DNS providers, certificate management, headless browser) are in separate packages and satisfy `aitm` interfaces implicitly via Go structural typing.

## Requirements

- Go 1.22+
- No CGO required — all dependencies are pure Go

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
autocert: true
phishlets_dir: /etc/mirage/phishlets
redirectors_dir: /etc/mirage/redirectors
dns_providers:
  - alias: cf-main
    provider: cloudflare
    settings:
      api_token: YOUR_TOKEN
```

Validate a config file without starting the daemon:

```bash
miraged --config /etc/mirage/miraged.yaml validate
```

## Usage

Start the daemon:

```bash
miraged --config /etc/mirage/miraged.yaml
```

Connect the CLI to a running daemon:

```bash
mirage server add https://<server-ip>:443 --alias prod --token <enrollment-token>
```

Manage phishlets, lures, and sessions:

```bash
mirage phishlets list
mirage phishlets enable microsoft --hostname login.phish.example.com
mirage lures create microsoft --redirect https://portal.office.com
mirage lures url 0
mirage sessions list
mirage sessions export <id> --out cookies.json
```

Drop into the interactive REPL by running `mirage` with no subcommand:

```bash
mirage --server prod
# mirage [prod]>
```

## Testing

```bash
make test
```

## Project Layout

```
aitm/           Core domain types, interfaces, and service structs
cmd/miraged/    Daemon entry point
cmd/mirage/     CLI client entry point
config/         Config file parsing and validation
store/
  sqlite/       SQLite implementations of aitm store interfaces
  mem/          In-memory implementations for use in tests
```
