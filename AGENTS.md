# Agent Instructions

This file is the starting point for agents working in this repository.

## First Reads

- `README.md` for the API, configuration and behavior.
- `PLAN.md` for the current work ledger index.
- `docs/agentic_work_ledger.md` for the project management convention.

## Work Ledger Rules

- Keep `PLAN.md` as a concise index, not a full status document.
- Store task details under `docs/tasks/`, and represent their state by
  moving files between `pending`, `current`, `blocked` and `done`.
- Record bugs under `docs/bugs/`, and decisions under `docs/decisions/`.
- Update the relevant ledger file with evidence before declaring work
  complete.

## Project Notes

| Path | Contents |
| --- | --- |
| `src/api.rs` | Public router: `/hooks` with sender authentication, consumer reads, filters, long-poll, event JSON. |
| `src/admin.rs` | Admin router: the console's assets and `/api/private/v1`. |
| `src/admin_ui/` | The console's HTML, CSS and JS, built into the binary. The base CSS comes from Model Relay's console. |
| `src/tokens.rs` | Token kinds, generation, fingerprints, and the `TokenStore` trait. |
| `src/store.rs` | The `EventStore` and `TokenStore` traits' SQLite implementation and its migrations. The HTTP layers must use only the traits. |
| `src/verify.rs` | Signature checks and sender classification. |
| `src/config.rs` | `WEBHOOK_SINK_*` environment variables. |
| `src/main.rs` | Startup, retention task, graceful shutdown. |
| `tests/api.rs` | HTTP tests through the real router. |

## Invariants

These are the API contract; change them only with an ADR:

- **Store, then acknowledge.** A delivery is committed before the `2xx`.
- **Byte-exact storage.** Bodies are stored as received, never re-encoded.
- **Cursors.** Sequence numbers only grow and are never reused, gaps
  included.
- **Dedupe.** A delivery ID is deduplicated per channel.
- **Tokens.** Every delivery needs a sender token, and every read a
  consumer token.
- **Signatures decide.** A delivery with a signature is judged by the
  signature alone.
- **Secrets at rest.** Consumer values are stored only as fingerprints.
  Values are never listed, and credential headers are never stored.
- **Untrusted payloads.** The console writes untrusted payloads only with
  `textContent`.

## Development Commands

- Tests: `make test`, which is `cargo test`.
- Lint: `make lint`, which runs fmt and clippy with `-D warnings` in the
  Rust image. The host toolchain may lack rustfmt and clippy.
- Image: `make image`. The build stage runs fmt, clippy and tests, and
  fails on any of them.

## Breadboard

Breadboard deploys this sink. Its deployment wiring lives in the Breadboard
repository, not here:

- `deploy/k8s/31-webhook-sink.yaml`
- `deploy/scripts/05n-build-webhook-sink.sh`
- `deploy/scripts/28-deploy-webhook-sink.sh`
- `make host-rebuild-webhook-sink`
