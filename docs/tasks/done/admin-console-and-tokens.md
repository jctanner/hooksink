# Task: Admin Console and Tokens

## Goal

Require tokens everywhere:

- senders authenticate with sender tokens, which are their signing secrets;
- consumers authenticate with consumer tokens;
- an admin console, like Model Relay's, issues and revokes tokens and lets
  admins browse events.

Breadboard gets one default sender token and one default consumer token.
Events are bucketed by query-time filters. See
[ADR-0002](../../decisions/ADR-0002-sender-tokens-are-signing-secrets.md).

## Acceptance Criteria

- [x] **Sender authentication:**
  - [x] HMAC with any active sender token (`X-Hub-Signature-256` and
        `X-Hub-Signature`), `X-Gitlab-Token`, Bearer, and `?token=`.
  - [x] A signature that matches no token is rejected even with a valid
        bearer token; a consumer token is never a sender token.
  - [x] Each event records the token and the method.
- [x] **Consumers:** every read needs an active consumer token, and a sender
      token is rejected. Consumers can no longer reset events.
- [x] **Filters:** `channel`, `source`, `event` and `sender`, repeated or
      comma-separated, on `/events`, on long-polls, and in the admin
      listing.
- [x] **Admin listener:**
  - [x] a separate port, with the admin key compared in constant time;
  - [x] the console shell is public, its data is not;
  - [x] the admin API is not served on the public port.
- [x] **Tokens:**
  - [x] Issue, rotate and revoke.
  - [x] Values are shown once and never listed.
  - [x] Consumer values are stored only as fingerprints; a sender's value
        is discarded on revocation.
- [x] **Defaults:** created or adopted from configuration at startup; a
      revoked default stays revoked.
- [x] **Upgrade:** a first-release database (with its `signature_valid`
      column) is migrated in place, with its events kept.
- [x] **Checks:** fmt, clippy (`-D warnings`) and tests pass in the image
      build.

## Status

Done

## Validation

**Tests:** 18 unit tests and 19 HTTP tests pass (`cargo test` and the image
build). `make lint` is clean.

**Breadboard, 2026-10-25:**

- **Deploy:** the deploy script created the `webhook-sink-tokens` Secret,
  and the sink adopted both defaults at startup. The 2 events from the
  first release survived the migration.
- **Through the proxy:**
  - the console shell returned 200;
  - the admin API returned 401 without the key, and 404 on the public
    host;
  - an unauthenticated post and an unauthenticated read both returned
    401;
  - a post signed with the default sender token returned 202.
- **Jira:** a webhook with the default sender token as its secret
  delivered `jira:issue_created` for TEST-2. A consumer long-polling with
  `source=jira&event=jira:issue_created` received it after 1.64 s. Sender:
  `default-sender`, method `hmac`.
- **GitHub emulator:** its `deliver_webhook()`, with the hook secret set to
  the default sender token, got a 202. Sender: `default-sender`, method
  `hmac`.
- **Console, in headless Chrome:**
  - a wrong key was rejected, and the right key connected;
  - a filtered event list, and the detail tabs (payload, headers with the
    signature, raw);
  - a sender token issued, its value shown once with usage instructions,
    then revoked;
  - no page errors. The only console errors were the favicon 404 and the
    deliberate wrong-key 401.
- **Phone width (390 px):** the page overflowed at first. The cause was the
  hidden `Actions` header label escaping its table, and the nav not
  wrapping. Both are fixed with Model Relay's own rules, and the page now
  fits on every view.

## Follow-up: insecure reveal mode

[ADR-0003](../../decisions/ADR-0003-insecure-reveal-mode.md) adds
`WEBHOOK_SINK_INSECURE_REVEAL_TOKENS`, which Breadboard turns on.

**Tests:** 20 unit and 21 HTTP tests pass, and lint is clean. The new
tests cover:

- consumer values kept, then deleted when the mode is turned off;
- the default consumer value backfilled at startup;
- `403` outside the mode;
- every active value revealed in the mode;
- revoked and unknown tokens returning `404`;
- values never appearing in listings.

**Breadboard, 2026-10-25:**

- The sink logged its warning and backfilled the default consumer value.
- In headless Chrome:
  - the sidebar badge and the banner showed;
  - **Show** on the default consumer token matched the Secret's value
    exactly;
  - **Copy** on the default sender token put the Secret's value on the
    clipboard;
  - revoked tokens offered neither action;
  - no page errors.

