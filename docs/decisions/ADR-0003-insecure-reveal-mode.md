# ADR-0003: An Opt-In Insecure Mode Reveals Token Values

## Status

Accepted

## Context

[ADR-0002](ADR-0002-sender-tokens-are-signing-secrets.md) shows each token
value once, and stores consumer values only as fingerprints.

On a local Breadboard stack that is mostly friction. Wiring an emulator hook
or a consumer means fetching values from a Kubernetes Secret, or rotating a
token whose value was not copied. Model Relay's local admin key is plain
`admin` for the same reason.

## Decision

Add `HOOKSINK_INSECURE_REVEAL_TOKENS` (named
`WEBHOOK_SINK_INSECURE_REVEAL_TOKENS` until 2026-10-26), off by default. When it is on:

- consumer values are stored, as sender values already are;
- the default consumer token's value is backfilled from configuration;
- the admin API serves `GET /api/private/v1/tokens/{id}/value` for active
  tokens with a stored value;
- the console offers **Show** and **Copy**, and warns that the mode is on.

When it is off:

- the endpoint answers `403`;
- the sink deletes stored consumer values at startup, so secure mode never
  keeps consumer values left over from an earlier insecure run.

Values never appear in listings, revoked tokens are never revealed, and
each reveal is logged by token ID.

Breadboard sets the variable to `true` in its manifest. A shared or
internet-facing deployment leaves it off.

## Consequences

**Positive:**

- Locally, any token can be copied from the console when wiring a hook or a
  consumer.

**Negative:**

- With the mode on, the admin key and the database together expose every
  active credential. That is acceptable only where the admin key is itself
  a development default.
- A consumer token issued while the mode was off cannot be revealed until
  it is rotated.
