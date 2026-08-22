# remnawave-healthcheck

Health checker for a [Remnawave](https://remna.st) installation that keeps **no inventory of its own**.
Nodes, channels, expected exits and the required Xray version are all derived from the panel API.

Give it a panel URL, an API token and the subscription URL of a monitoring user — it figures out the rest.

## Usage

```sh
remnawave-healthcheck \
  --panel-url https://panel.example.com \
  --api-token "$REMNAWAVE_API_TOKEN" \
  --subscription-url https://sub.example.com/abc123
```

The same three values can be given as environment variables instead of flags — `REMNAWAVE_PANEL_URL`,
`REMNAWAVE_API_TOKEN`, `REMNAWAVE_SUBSCRIPTION_URL` — which is how a CI job would normally run it. Add
`TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` (optionally `TELEGRAM_THREAD_ID` for a supergroup topic) to
get alerted when something changes. Run `remnawave-healthcheck --help` for the full flag list, including
`--no-ssh`, `--no-channels`, `--test-alert`, and the tuning knobs (`--concurrency`, `--probe-timeout-secs`,
`--cert-warn-days`, `--config-warn-days`, `--echo-url`).

## What it checks

- **Every client-facing channel** the monitoring user can see: an Xray tunnel is actually run through
  each one and the traffic's real exit IP is compared against what the expected node reports as its own
  egress address.
- **Node state as the panel itself reports it** — connected, disabled, last status message.
- **Subscription coverage** — whether the rendered subscription serves as many channels as the panel
  resolved for the monitoring user.
- **Inbounds not covered by monitoring** — an inbound that is live on a node but never reaches the
  monitoring user's subscription, typically because the user was never added to that squad.
- **Xray version drift** across nodes — client and node must agree on protocol features to talk to each
  other at all.
- **Node-side facts over SSH** — the node container running, containers up and healthy, expected ports
  listening publicly, provisioned users present in the logs, config-push freshness, the node's own
  external address, TLS certificate expiry, and the acme.sh renewal mechanism itself (not just the
  certificate's remaining days).

## What it needs

- A panel API token with the `nodes`, `config-profiles`, and `subscription` scopes. A regular admin
  login JWT will not work here — the panel requires a token created for API access.
- A monitoring user whose subscription includes every squad you want checked. A channel the monitoring
  user cannot see is a channel this tool cannot check.
- `ssh` in `PATH` and a key already loaded in `ssh-agent` (or otherwise usable non-interactively) for
  the node-side checks. Skip them with `--no-ssh` if that access is not available.

## What it does not do

- It never changes anything in the panel or on a node — every check is read-only.
- It keeps no inventory file: nothing needs to be told which nodes or channels exist, or updated when
  they change.
- It needs no configuration file — panel URL, token, subscription URL and Telegram credentials are the
  whole setup, via flags or environment variables.
