# remnawave-healthcheck

Health checker for a [Remnawave](https://remna.st) **3.3+** installation that keeps no inventory of its
own: nodes, channels, expected exits and the Xray version all come from the panel API. Made to run from
CI on a schedule and report to Telegram after every run.

## Usage

```sh
REMNAWAVE_PANEL_URL=https://panel.example.com \
REMNAWAVE_API_TOKEN=... \
REMNAWAVE_USER_ID=42 \
TELEGRAM_BOT_TOKEN=... TELEGRAM_CHAT_ID=... \
SSH_PRIVATE_KEY="$(cat ~/.ssh/id_ed25519)" \
remnawave-healthcheck
```

Every setting is an environment variable and a flag; `remnawave-healthcheck --help` prints the whole
table with defaults. Three are required: the panel URL, an API token, and the numeric id of a monitoring
user whose subscription covers every squad you want checked. `examples/healthcheck.yml` is a
ready-made GitHub Actions workflow that downloads a release binary and runs it every six hours.

Exit code `0`: no FAIL (warnings do not break the build). `1`: at least one FAIL. `2`: the run could not
do its job (bad configuration, unreadable panel, undelivered Telegram message).

## What it checks

- **From the panel API** — node status with the panel's own reason, users online, config age
  (`xrayUptime`), host load and memory, Xray and remnanode version drift across nodes, subscription
  coverage (the rendered subscription serves exactly the channels the panel resolved), inbounds the
  monitoring user cannot see.
- **From geocheck** (a job the panel runs on each node) — the node's real egress address and ASN,
  which country the world sees it in versus what the panel says, IP reputation, connectivity to
  external services, geocheck's own findings, and how directly the node reaches the internet.
  The panel stores that report untyped, so its shape comes from the `geocheck` binary rather than
  from the panel; these checks read the `schema: 1` of
  [remnawave/geocheck](https://github.com/remnawave/geocheck) v0.3.0 and say so when a node
  answers with anything else.
- **From the runner** — TLS certificates of the panel and of the subscription host; both path forms of
  every xhttp inbound answer `400` (guards xray #6307).
- **Over SSH** (only what the API cannot tell) — containers running and healthy, inbound ports actually
  listening on a public address, node certificate expiry, and whether acme.sh renewal still works. A node
  that refuses SSH is one warning, not a wall of red.
- **Through a real Xray tunnel** — every channel of the monitoring user's subscription, run with the
  exact outbound the panel served, its exit compared with the expected node's egress address by
  following the routing graph of the config profiles (cascades included).

## What it needs

- An API token (not an admin login JWT) with the `nodes`, `config-profiles`, `by-id`, `raw`, `geocheck`
  and `geocheck-result` scopes.
- A monitoring user whose subscription includes every squad you want checked. If the panel limits devices
  per user, register one device for it (`POST /api/hwid/devices {hwid, userId}`) and pass its id as
  `REMNAWAVE_HWID`; otherwise the subscription answers with a placeholder and the tool says so.
- `ssh` in `PATH`. Give the key as `SSH_PRIVATE_KEY` (the tool writes it to a `0600` temp file for the
  run) or leave it to `ssh-agent`. `SSH_USER` defaults to `root` when a key is given and to your ssh config otherwise; `SSH_PORT` defaults to `22`; set
  `SSH_KNOWN_HOSTS` for strict host-key checking.

## Operational notes

- GitHub-hosted runners connect from changing IP addresses: a `ufw`/`fail2ban` allowlist for SSH on the
  nodes turns every node-side check into a warning. Either allow key-only SSH from anywhere or use a
  self-hosted runner.
- In a public repository GitHub disables scheduled workflows after 60 days without commits.
- Requesting the panel API directly at the container, past the reverse proxy, drops the connection
  unless `X-Forwarded-For` and `X-Forwarded-Proto: https` are set. Use the public URL.
- The tool never changes anything in the panel or on a node, and keeps no state between runs.
