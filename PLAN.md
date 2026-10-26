# Plan

The webhook sink is a durable webhook receiver with cursor and long-poll
consumers. See `README.md`.

## Done

- [Initial implementation](docs/tasks/done/initial-implementation.md):
  storage, signatures, long-poll, image, and the Breadboard deployment.
- [Admin console and tokens](docs/tasks/done/admin-console-and-tokens.md):
  sender tokens as signing secrets, consumer tokens, default tokens,
  query-time filters, and the console on a separate admin listener.
- [Host and repository filters](docs/tasks/done/host-and-repo-filters.md):
  `host=` and `repo=` (with `org/*` prefixes), located from each payload at
  ingest and backfilled for older events.
- [Hooksink naming](docs/tasks/done/hooksink-naming.md): `HOOKSINK_*`
  configuration, and the package, binary and console named hooksink.

## Next

- Real GitHub as a source, out of scope for now. It needs a public ingress
  or tunnel, mandatory signatures on public channels, and a job that
  reconciles and redelivers failed deliveries through the GitHub API. See
  the Breadboard task's "Later: real GitHub" section.

## Decisions

- [ADR-0001: Rust, SQLite and one replica](docs/decisions/ADR-0001-rust-sqlite-single-replica.md)
- [ADR-0002: Sender tokens are signing secrets; filters instead of topics](docs/decisions/ADR-0002-sender-tokens-are-signing-secrets.md)
- [ADR-0003: An opt-in insecure mode reveals token values](docs/decisions/ADR-0003-insecure-reveal-mode.md)
