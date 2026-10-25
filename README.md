# webhook-sink-service

The webhook sink is a small, durable receiver for webhooks. Senders, such as
GitHub, Jira, GitLab or scripts, post deliveries to a named channel.
Consumers read them back in order with a cursor and filters, and can
long-poll for new ones, so they need no HTTP server of their own. An admin
console issues and revokes the tokens that senders and consumers use, and
lets you browse what has arrived.

The sink is a single static Rust binary (`axum`, `tokio`) that stores events
and tokens in SQLite. The container image is about 2.5 MB, and an idle
process uses about 1 MB of memory.

## Listeners

| Listener | Default | Serves |
| --- | --- | --- |
| Public | `:8080` | `POST /hooks/{channel}`, consumer reads, `/healthz` |
| Admin | `:8081` | The console at `/admin/`, and the private API under `/api/private/v1` |

The two listeners are separate, so `/hooks` can later be exposed publicly,
for example through a tunnel for real GitHub, without exposing token
management. The admin listener starts only when an admin key is configured.

## Tokens

| Kind | Prefix | Used by | Stored as |
| --- | --- | --- | --- |
| Sender | `whs_` | Webhook senders | The value, because signature checks need it |
| Consumer | `whc_` | Readers of `/events` | A SHA-256 fingerprint only, or also the value in insecure reveal mode |

The admin key is not a token in the store. It comes from configuration.

A token's value is shown once, when it is issued or rotated. Rotating keeps
the token's ID and name and replaces its value. Revoking is permanent, and
it also discards a sender token's stored value.

**Default tokens.** At startup, `WEBHOOK_SINK_DEFAULT_SENDER_TOKEN` and
`WEBHOOK_SINK_DEFAULT_CONSUMER_TOKEN` become the default token of each kind:

- A token with that value is created if it does not exist.
- If the configured value changes, the new token becomes the default. The
  old one stays active until an admin revokes it.
- A default an admin has revoked stays revoked across restarts. The sink
  logs a warning, and the deployment secret needs a new value.

### Insecure reveal mode

With `WEBHOOK_SINK_INSECURE_REVEAL_TOKENS=true`:

- consumer token values are stored, as sender values always are;
- the console shows **Show** and **Copy** for every active token whose
  value is stored;
- the console shows a warning badge and banner;
- the admin API serves `GET /api/private/v1/tokens/{id}/value`.

Without the mode, that endpoint answers `403`.

A consumer token issued while the mode was off has no stored value until it
is rotated. The default consumer token is the exception: it is backfilled
from configuration at startup.

When the mode is turned off again, the sink deletes stored consumer values
at startup, and only fingerprints remain.

Revoked tokens are never revealed, and values never appear in token
listings. Each reveal is logged, with the token's ID but not its value.

### Sender authentication

A sender token's value is also the webhook signing secret:

- **GitHub and Jira:** paste the token as the hook's `secret`. GitHub signs
  the body with HMAC-SHA256 and sends `X-Hub-Signature-256`; Jira sends
  `X-Hub-Signature`. The sink finds the active sender token that produced
  the signature. The token never appears in a URL, and the signature also
  proves the body was not altered.
- **Senders that cannot sign** can present the token itself, checked in
  this order:
  1. `X-Gitlab-Token`, which is how GitLab sends its secret token;
  2. `Authorization: Bearer <token>`;
  3. `?token=<token>` on the URL, as a last resort.

A delivery that carries a signature is judged by the signature alone. If no
active sender token produced it, the delivery is rejected, even when a valid
bearer token is also present. GitHub's legacy SHA-1 signature is not
accepted.

Each stored event records which token authenticated it and how: `hmac`,
`gitlab-token`, `bearer` or `query`. Credential headers are never stored;
their values appear as `[redacted]`:

- `X-Gitlab-Token`;
- `Authorization`;
- `Cookie`.

## Public API

| Method and path | Auth | Behavior |
| --- | --- | --- |
| `POST /hooks/{channel}` | Sender | Stores a delivery. See the response codes below. |
| `GET /events?channel=&source=&event=&sender=&after=&limit=&wait=` | Consumer | Matching events with `seq > after`, oldest first. Returns `{"events": [...], "next_after": N}`. |
| `GET /events/{seq}` | Consumer | One event as JSON. |
| `GET /events/{seq}/raw` | Consumer | The original body bytes, with the original `Content-Type`. |
| `GET /channels` | Consumer | Each channel's count and latest `seq`. |
| `GET /`, `GET /healthz` | None | Service information and liveness. |

`POST /hooks/{channel}` answers with one of these codes:

| Status | Meaning |
| --- | --- |
| `202` | Stored. The body is `{"seq": N, "duplicate": false}`. |
| `200` | An already-stored delivery ID on this channel, so nothing was stored again. The body is `{"seq": N, "duplicate": true}`. |
| `401` | No valid sender token. |
| `413` | The body is over the cap. |
| `400` | The channel name is invalid. |

Channel names use letters, digits, `-`, `_` and `.`. They are at most 64
characters long and must not start with `.`.

### Filters

Filters are applied when the events are read; there are no stored topics.

| Parameter | Matches |
| --- | --- |
| `channel` | The channel the delivery was posted to |
| `source` | `github`, `gitlab`, `jira` or `generic` |
| `event` | The event type, such as `issues`, `pull_request`, `Push Hook` or `jira:issue_created` |
| `sender` | A sender token ID, such as `tok_…` |

Each parameter can repeat, or hold a comma-separated list, and matches any
of its values. Different parameters combine with AND:

```text
/events?source=github&event=issues,pull_request
```

### Consuming

Keep the last `next_after` you saw and ask for anything newer:

```bash
after=0
while true; do
  page=$(curl -s -H "Authorization: Bearer $WHC_TOKEN" \
    "http://webhook-sink/events?source=github&after=$after&wait=30")
  # ... handle .events ...
  after=$(jq .next_after <<<"$page")
done
```

With `wait`, a request that finds nothing waits, up to that many seconds
(capped by `WEBHOOK_SINK_MAX_WAIT_SECONDS`), and returns as soon as a
matching event arrives.

Sequence numbers only grow. They are never reused, even after a reset, so a
saved cursor stays valid.

### Event JSON

Each event has these fields:

- `seq`, `channel`, `source`, `event`, `delivery_id`;
- `received_at`, an RFC 3339 timestamp;
- `sender`, as `{token_id, name, method}`;
- `headers`, `content_type`, `size`.

The body appears as exactly one of these:

| Field | When |
| --- | --- |
| `payload` | The body parses as JSON. |
| `body` | The body is other UTF-8 text. |
| `body_base64` | Anything else. |

The sink classifies each delivery from its headers:

| `source` | Detected by | `event` | `delivery_id` |
| --- | --- | --- | --- |
| `github` | `X-GitHub-Event` | that header | `X-GitHub-Delivery` |
| `gitlab` | `X-Gitlab-Event` | that header | `Idempotency-Key`, or else `X-Gitlab-Event-UUID` |
| `jira` | `X-Atlassian-Webhook-Identifier`, or a JSON `webhookEvent` | `webhookEvent` | `X-Atlassian-Webhook-Identifier` |
| `generic` | anything else | none | `Idempotency-Key` |

Bodies and signature headers are stored as received, so a signature can be
re-verified later from `/events/{seq}/raw`.

## Admin console and API

Open `/admin/` on the admin listener and enter the admin key. The key stays
in the tab's memory only. The console has four views:

| View | What it does |
| --- | --- |
| Overview | Totals, setup instructions for senders and consumers, sources, event types, and channels, each channel with a reset. |
| Events | Newest first, with filters. A row opens the payload, headers and raw body. |
| Sender tokens | Issue, rotate and revoke sender tokens. |
| Consumer tokens | Issue, rotate and revoke consumer tokens. |

The console uses this API, which requires `Authorization: Bearer <admin
key>`:

| Method and path | Behavior |
| --- | --- |
| `GET /api/private/v1/overview` | Totals, sources, event types, active token counts, and the public URL |
| `GET /api/private/v1/events?…&before=&limit=` | Newest first, with the same filters. Returns `next_before`. |
| `GET /api/private/v1/events/{seq}`, `…/raw` | One event |
| `DELETE /api/private/v1/events[?channel=]` | Reset one channel or all of them. Returns `{"deleted": N}`. |
| `GET /api/private/v1/channels` | Channel summaries |
| `GET /api/private/v1/tokens[?kind=]` | Tokens, never their values |
| `POST /api/private/v1/tokens` | Issue a token. The body is `{"kind", "name", "description"?}`. Returns `{token, value}`. |
| `POST /api/private/v1/tokens/{id}/rotate` | Replace the value. Returns `{token, value}`. |
| `POST /api/private/v1/tokens/{id}/revoke` | Revoke the token. |
| `GET /api/private/v1/tokens/{id}/value` | A stored value, in insecure reveal mode only |

## Configuration

Each secret can be given directly, or as a path in the variable of the same
name with `_FILE` added.

| Variable | Default | Meaning |
| --- | --- | --- |
| `WEBHOOK_SINK_LISTEN` | `0.0.0.0:8080` | Public listener |
| `WEBHOOK_SINK_ADMIN_LISTEN` | `0.0.0.0:8081` | Admin listener |
| `WEBHOOK_SINK_ADMIN_KEY[_FILE]` | unset | Admin key. Without it, the admin listener does not start. |
| `WEBHOOK_SINK_DEFAULT_SENDER_TOKEN[_FILE]` | unset | Made the default sender token at startup |
| `WEBHOOK_SINK_DEFAULT_CONSUMER_TOKEN[_FILE]` | unset | Made the default consumer token at startup |
| `WEBHOOK_SINK_PUBLIC_URL` | unset | Base URL for senders and consumers, shown in the console |
| `WEBHOOK_SINK_INSECURE_REVEAL_TOKENS` | `false` | Insecure reveal mode, for local development. See below. |
| `WEBHOOK_SINK_DB` | `/data/events.sqlite` | SQLite database, in WAL mode with `synchronous=FULL` |
| `WEBHOOK_SINK_MAX_BODY_BYTES` | `26214400` | Body cap, 25 MB, the same as GitHub's |
| `WEBHOOK_SINK_MAX_WAIT_SECONDS` | `60` | Long-poll cap |
| `WEBHOOK_SINK_RETENTION_MAX_AGE_SECONDS` | `604800` | Delete events older than this. `0` disables the limit. |
| `WEBHOOK_SINK_RETENTION_MAX_EVENTS` | `100000` | Keep at most this many events. `0` disables the limit. |

Retention runs once a minute. On SIGTERM both listeners stop accepting
connections, and waiting long-polls are released immediately.

A database from the first release, which used per-channel secret files, is
upgraded in place when the sink starts. Its events are kept.

## Development

```bash
make test        # cargo test
make run         # run locally on :8080 with ./data/events.sqlite
make image       # container build; it runs fmt, clippy and tests first
make lint        # fmt check and clippy, in the build image (host needs no rustfmt or clippy)
make fmt         # apply rustfmt, in the build image
```

`make run` starts without an admin key or default tokens, so it accepts no
deliveries. Set `WEBHOOK_SINK_ADMIN_KEY` and issue tokens in the console, or
set the default token variables.

The sink keeps one SQLite writer, so run one replica. See
[ADR-0001](docs/decisions/ADR-0001-rust-sqlite-single-replica.md) and
[ADR-0002](docs/decisions/ADR-0002-sender-tokens-are-signing-secrets.md).
