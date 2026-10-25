# Task: Initial Implementation

## Goal

Implement the sink that Breadboard's
`.ledger/tasks/done/webhook-sink-service.md` describes: durable storage,
signature checks, cursor and long-poll consumers, and a small image.

## Acceptance Criteria

- [x] Signature checks: valid, bad and missing signatures; channels without
      a secret; Jira's `X-Hub-Signature`; GitLab's token.
- [x] Dedupe per channel, with no gaps left in `seq` by a duplicate.
- [x] Cursor paging, a channel filter, and channel summaries.
- [x] Long-poll: woken by an insert; not woken by another channel's event;
      returns empty on timeout; capped; released on shutdown.
- [x] Body cap returns 413; retention by age and by count; reset of one
      channel or all; `seq` never reused after a reset.
- [x] Raw bodies are byte-exact, and their signatures re-verify from the
      stored headers.
- [x] An optional API token guards consumer endpoints, but not `/hooks` or
      `/healthz`.
- [x] Static image built, with fmt, clippy (`-D warnings`) and tests run in
      the build.

## Status

Done

## Validation

**Tests:** `cargo test` passes 10 unit tests and 14 HTTP tests. The image
build runs the same tests after `cargo fmt --check` and `cargo clippy
--all-targets -D warnings`.

**Image and memory:** the image is 2.23 MB. Running locally, the container
used about 1 MB RSS, and `podman stop` exited with code 0.

**Bug found and fixed:** a local smoke test showed that a duplicate insert
consumed an AUTOINCREMENT value, so `seq` jumped from 1 to 3. The store now
looks the delivery ID up under the connection lock before inserting, and a
unit test asserts there is no gap.

**Breadboard deployment** (2026-10-25):

- *Jira emulator:* a signed `jira:issue_created` delivery reached a
  long-poll consumer 1.3 s after the issue was created; that includes
  Jira's 1 s outbox poll. `signature_valid` was true, and the HMAC
  re-verified from `/raw`.
- *GitHub emulator:* its own `deliver_webhook()` received a 202 in 0.11 s,
  as source `github`, event `issues`, with a valid signature.
- *Ingress proxy:* `https://webhook-sink.local/channels` answered through
  the proxy.
