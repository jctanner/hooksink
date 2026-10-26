# Hooksink naming

## Goal

The project is branded hooksink; its configuration, package and binary carry
that name.

## Environment variables

Every `WEBHOOK_SINK_*` variable is now `HOOKSINK_*`, with the same suffix:
`LISTEN`, `ADMIN_LISTEN`, `DB`, `ADMIN_KEY`, `DEFAULT_SENDER_TOKEN`,
`DEFAULT_CONSUMER_TOKEN` (each also as `*_FILE`), `PUBLIC_URL`,
`INSECURE_REVEAL_TOKENS`, `MAX_BODY_BYTES`, `MAX_WAIT_SECONDS`,
`RETENTION_MAX_AGE_SECONDS` and `RETENTION_MAX_EVENTS`. The old names are not
read; Breadboard's manifest (`deploy/k8s/31-hooksink.yaml`) changed with it.

Updated: `src/config.rs`, the messages that name a variable, the Dockerfile
defaults, `make run`, the README, the console's reveal warning, ADR-0003 and
`AGENTS.md` (which also now lists Breadboard's renamed hooksink files).
Earlier task records keep the old names as history.

## Package and binary

- The Cargo package and library are `hooksink` (was `webhook-sink-service`,
  imported as `webhook_sink_service`), and the binary is `hooksink` (was
  `webhook-sink`). The image runs `/hooksink`, and `make image` tags
  `hooksink:latest`.
- Log lines, the console's title and brand, its version label, and the
  `service` field of `GET /` now say `hooksink`.
- The README is titled `hooksink`.

## Evidence

- `make test`: 45 tests pass. `make lint`: fmt and clippy clean.
- Deployed on Breadboard with `make host-rebuild-hooksink`; see the
  Breadboard task record for the live checks.
