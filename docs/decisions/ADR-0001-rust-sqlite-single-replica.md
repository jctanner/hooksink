# ADR-0001: Rust, SQLite and One Replica

## Status

Accepted

## Context

Breadboard needs somewhere to send emulator webhooks, from which consumers
can pull new events. Real GitHub webhooks are expected later. Breadboard's
[ADR-0013](../../../../.ledger/decisions/ADR-0013-webhook-sink-in-rust.md)
compared the options and chose a small purpose-built Rust service.

## Decision

- **Server:** `axum` on `tokio`, built as a static musl binary on a
  `scratch` image.
- **Storage:** SQLite in WAL mode with `synchronous=FULL`, behind the
  `EventStore` trait, with one replica.
- **Cursor:** consumers keep their own cursor, the `seq` value. The server
  keeps no consumer groups or acks.
- **Long-poll:** one `watch` channel holds the newest `seq`. Every waiter
  wakes on any insert and queries again for its own channel.

## Consequences

**Positive:**

- The image is 2.23 MB and the idle process uses about 1 MB of memory,
  both measured.
- Consumers need only HTTP.
- The backend can be replaced without changing the API.

**Negative:**

- There is one writer, and so one replica.
- A busy channel wakes waiters on quiet channels; each wake costs one
  indexed query.

Move to Postgres or NATS JetStream only when one of these is needed:

- more than one replica;
- several consumers that need acks or redelivery on the server side;
- durability beyond one volume.

Event volume alone is not a reason to move.
