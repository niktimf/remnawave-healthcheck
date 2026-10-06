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

- **From the panel API and GitHub** — the panel's own version against the newest stable release of
  [remnawave/panel](https://github.com/remnawave/panel): a major version behind fails, a minor warns,
  a patch is named and nothing more. This is the only request that leaves for anything but the panel
  and its nodes; a GitHub that rate-limits or does not answer is a version that could not be read,
  never a panel declared out of date. `--no-upstream` skips it.
- **From the panel API** — node status with the panel's own reason, users online, config age
  (`xrayUptime`), host load and memory, Xray and remnanode version drift across nodes, subscription
  coverage (the rendered subscription serves exactly the channels the panel resolved), and inbounds serving
  no channel of the monitoring user — a host kept out of this subscription type and a host switched off in the
  panel are each named as such, an inbound no host and no cascade leads to is reported as the configuration
  error it is, and the receiving end of a cascade, which no client ever dials, is passed over.
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
  Once a tunnel shows its exit, a 1 MB file (`REMNAWAVE_DOWNLOAD_URL`) is
  downloaded through it: a download with no byte for 10 s or still running
  after `REMNAWAVE_DOWNLOAD_TIMEOUT_SECS` (30 s) warns, and one that stops
  at 14-34 KB is named as the freeze it looks like. When the file reaches
  no channel at all, the channels stay green and one `download target` row
  warns. That is about 1 MB per channel per run; `--no-download` skips it.
- **Services through the exit** — Gemini, NotebookLM, YouTube Premium,
  ChatGPT, Claude, Copilot, Grok and the OpenAI, Anthropic and xAI APIs,
  asked once per exit node through a fresh Xray with the first channel whose
  tunnel came out at that exit's egress address. The answer is the one
  clients get under the exit profile's routing rules (direct, WARP or a
  cascade to another exit). A positive refusal fails the row, and a page
  without a known marker (a Cloudflare challenge, new markup) warns. Exits in
  RU are skipped. Next to it, `services direct` repeats what geocheck found
  for the node's own address (which country Google sees, which services
  refuse it). That line is always OK. `--no-services` switches the
  stage off and keeps the rows, marked as disabled;
  `REMNAWAVE_SERVICE_TIMEOUT_SECS` bounds each request (15 s).
- **YouTube country per exit** — the same tunnel then asks the YouTube home
  page which country it serves the exit's content for (`countryCode`, or
  `INNERTUBE_CONTEXT_GL` where the page lacks it): one `youtube country` row
  per exit. `REMNAWAVE_EXPECTED_YOUTUBE` (`node-a=RU,node-b=RU`, node names
  as the panel shows them) sets the country an exit should stay in, and any
  other country warns. YouTube refuses Premium in RU, so for an exit
  expected in RU that refusal is listed under `not counted` and leaves the
  `services` row alone. A malformed list is a configuration error (exit code
  2).
- **Auto-select entries** — a host whose XRAY-JSON template injects other hosts (`remnawave.
  injectHosts`) is served a balancer instead of an outbound of its own, so it has no exit to compare
  and its address is a placeholder. It is checked as what it is: the injector must have selected
  candidates at all, and at least two of the channels it routes through must be alive. A host the
  panel keeps out of the subscription type but a balancer carries — the auto-select-only host — is
  taken from that balancer and probed like any other channel, rather than going unchecked.

## What it needs

- An API token (not an admin login JWT) with the `nodes`, `config-profiles`, `by-id`, `raw`, `geocheck`
  and `geocheck-result` scopes, plus `metadata` for the version check — without it that one check warns
  and the rest of the run is unaffected.
- Optionally `GITHUB_TOKEN` for the release lookup: unauthenticated GitHub allows 60 requests an hour
  per address, and a hosted runner shares its address. Every Actions run already has the token.
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
