# Task: Host and Repository Filters

## Goal

Let consumers filter events by the sending system's host and by
repository, without depending on how each hook's channel is named.

## Design

**At ingest.** `verify::locate(source, body)` reads the host and the
repository from the payload; the README lists the fields per source. They
are stored in indexed `host` and `repo` columns.

**Filters.** `host=` and `repo=` take a list, like the other filters. A
`repo` value ending in `*` is a prefix match, using `LIKE` with `%`, `_`
and `\` escaped.

**Migration.** Older databases get the columns. A one-time backfill,
recorded in `PRAGMA user_version = 1`, locates their stored events.

**Console.**

- the Events view gains a host menu and a repository field that accepts
  `org/*`;
- the table gains a Repository column;
- the event detail shows the host and repository;
- the overview lists hosts and repositories.

## Acceptance Criteria

- [x] Host and repository are located for GitHub, GitLab and Jira payloads,
      and tolerate missing or malformed fields.
- [x] Exact and prefix filters work, and `_` in a prefix is literal. They
      combine with AND across parameters and OR within one.
- [x] Long-polls filtered by repository wake only for that repository.
- [x] Events from before the change are backfilled once.
- [x] The console filters, columns and facets work at desktop and phone
      widths.

## Status

Done

## Validation

**Tests:** 23 unit and 22 HTTP tests pass, and lint is clean. The new
tests cover:

- `locate` for each source;
- prefix filters and escaping;
- backfill of a first-release database, and that the backfill runs only
  once;
- an HTTP test of host and repository filters, a filtered long-poll, and
  the admin facets.

**Breadboard, 2026-10-25:**

- **Backfill:** after deploying, events stored before the change were
  located: the GitHub emulator's events as `github.local` and
  `admin/webhook-live-…`, and Jira's as `jira.local` and `TEST`.
- **No location found:** three hand-made test payloads from earlier have
  no `repository` and stay `null`, as designed.
- **Filters, through `https://webhook-sink.local`:**
  - `host=github.local` and `repo=admin/*` each returned the four GitHub
    events;
  - `host=jira.local&repo=TEST` returned the two Jira events;
  - `host=github.com` returned nothing.
- **Console, in headless Chrome at 1440, 1100 and 390 px:** filtering by
  host `github.local` and repository `admin/*` showed the four events, with
  no horizontal overflow and no page errors.
