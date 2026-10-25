# ADR-0002: Sender Tokens Are Signing Secrets; Filters Instead of Topics

## Status

Accepted

## Context

The first release had optional per-channel secrets and an optional single
API token. Without them, as it was deployed, anyone on the network could
read, delete and inject events. The sink needs an admin console that issues
separate tokens to senders and to consumers, with a default token of each
kind for Breadboard's emulators and consumers.

Webhook senders limit how a sender can authenticate. A GitHub hook has only
a URL, a content type, a `secret`, and an SSL setting:

- it cannot send custom headers;
- it cannot use mutual TLS or OAuth to reach the destination;
- its only documented authentication is the HMAC signature in
  `X-Hub-Signature-256`.

Jira signs the same way. GitLab sends its secret token in plain text.

A token in the URL works with any sender, but it is visible in every hook
configuration and in proxy logs, and it does not protect the body.

## Decision

**Senders.** A sender token's value is the webhook signing secret. The sink
identifies the token by checking the HMAC against each active sender token:

- A request that carries a signature is judged by the signature alone.
- Without a signature, the token itself is accepted from `X-Gitlab-Token`,
  `Authorization: Bearer`, or `?token=`, in that order.
- Sender values are stored, because HMAC checks need them. They are
  discarded on revocation.

**Consumers.** Consumers use bearer consumer tokens, stored only as SHA-256
fingerprints. Resetting events is an admin action, not a consumer one.

**Admin.** The admin key comes from configuration. It is checked on a
separate admin listener that serves the console, built into the binary, and
`/api/private/v1`, as Model Relay does.

**Defaults.** The default sender and consumer tokens come from
configuration and are created or adopted at startup. An admin's revocation
of a default outlives restarts.

**Filters.** Events are bucketed only by query-time filters on `channel`,
`source`, `event` and `sender`. Each filter takes a list of values; the
filters combine with AND. There are no stored topics.

## Consequences

**Positive:**

- GitHub and Jira hooks authenticate with their native mechanism, and the
  token never appears in a URL.
- Each delivery records which sender token sent it.
- Consumers need only a bearer token.

**Negative:**

- Each signed delivery costs one HMAC per active sender token. That is
  negligible at tens of tokens.
- Sender values sit in the database, which is protected like any secret
  store, on a PVC readable only by the pod.
- Without stored topics, tokens cannot be limited to a subset of events,
  and a consumer has to repeat its filters on every request. If either
  matters later, add named topics as saved filters, which keeps the event
  model unchanged.
