//! Event and token storage.
//!
//! The HTTP layer talks to [`EventStore`] and [`TokenStore`] only, so a
//! Postgres or NATS JetStream backend can replace SQLite without changing
//! the API. Sequence numbers are the consumer cursor: they only grow and are
//! never reused, even after a reset.

use std::fmt;
use std::path::Path;
use std::sync::Mutex;

use rusqlite::types::Value as SqlValue;
use rusqlite::{Connection, OptionalExtension, Row, params, params_from_iter};

use crate::tokens::{
    DefaultToken, NewToken, SenderKey, Token, TokenKind, TokenStore, display_prefix, fingerprint,
    new_id,
};
use crate::verify::locate;

#[derive(Debug)]
pub struct StoreError(String);

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for StoreError {}

impl StoreError {
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        Self(e.to_string())
    }
}

impl From<serde_json::Error> for StoreError {
    fn from(e: serde_json::Error) -> Self {
        Self(e.to_string())
    }
}

pub type StoreResult<T> = Result<T, StoreError>;

/// A delivery as received, before it has a sequence number.
#[derive(Clone, Debug, PartialEq)]
pub struct NewEvent {
    pub channel: String,
    pub source: String,
    pub delivery_id: Option<String>,
    pub event: Option<String>,
    pub received_at_ms: i64,
    /// Header names and values in arrival order, duplicates kept.
    pub headers: Vec<(String, String)>,
    pub content_type: Option<String>,
    /// The body exactly as received.
    pub body: Vec<u8>,
    /// The sender token that authenticated the delivery.
    pub sender_token_id: Option<String>,
    /// How it authenticated: `hmac`, `gitlab-token`, `bearer` or `query`.
    pub auth_method: Option<String>,
    /// The sending system's host, from the payload; see `verify::locate`.
    pub host: Option<String>,
    /// The repository, GitLab project or Jira project, from the payload.
    pub repo: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Event {
    pub seq: i64,
    pub data: NewEvent,
    /// The sender token's current name, if it still exists.
    pub sender_name: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Inserted {
    New(i64),
    /// The channel already holds this delivery ID; the existing `seq`.
    Duplicate(i64),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelSummary {
    pub channel: String,
    pub count: u64,
    pub latest_seq: i64,
    pub latest_received_at_ms: i64,
}

/// Query-time filters. Each list matches any of its values; an empty list
/// matches everything. Lists combine with AND.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EventFilter {
    pub channels: Vec<String>,
    pub sources: Vec<String>,
    pub events: Vec<String>,
    /// Sender token IDs.
    pub senders: Vec<String>,
    pub hosts: Vec<String>,
    /// A value ending in `*` matches by prefix, such as `org/*`.
    pub repos: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Facets {
    pub total: u64,
    pub latest_seq: i64,
    pub sources: Vec<(String, u64)>,
    pub events: Vec<(String, u64)>,
    pub hosts: Vec<(String, u64)>,
    pub repos: Vec<(String, u64)>,
}

pub trait EventStore: Send + Sync {
    fn insert(&self, event: &NewEvent) -> StoreResult<Inserted>;
    /// Matching events with `seq > after`, oldest first.
    fn list(&self, filter: &EventFilter, after: i64, limit: usize) -> StoreResult<Vec<Event>>;
    /// Matching events with `seq < before` (or the newest), newest first.
    fn list_recent(
        &self,
        filter: &EventFilter,
        before: Option<i64>,
        limit: usize,
    ) -> StoreResult<Vec<Event>>;
    fn get(&self, seq: i64) -> StoreResult<Option<Event>>;
    /// Delete one channel's events, or all events; returns the count.
    fn delete(&self, channel: Option<&str>) -> StoreResult<u64>;
    fn channels(&self) -> StoreResult<Vec<ChannelSummary>>;
    /// Totals and the distinct sources and event types, for filter menus.
    fn facets(&self) -> StoreResult<Facets>;
    /// Delete events received before `older_than_ms`, then all but the
    /// newest `keep_latest`; returns the count.
    fn trim(&self, older_than_ms: Option<i64>, keep_latest: Option<u64>) -> StoreResult<u64>;
}

pub struct SqliteStore {
    conn: Mutex<Connection>,
    /// Keep consumer token values as well as their fingerprints, so the
    /// admin console can show them. Off by default; see
    /// `HOOKSINK_INSECURE_REVEAL_TOKENS`.
    keep_consumer_values: bool,
}

const TABLES: &str = "
CREATE TABLE IF NOT EXISTS events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    channel TEXT NOT NULL,
    source TEXT NOT NULL,
    delivery_id TEXT,
    event TEXT,
    received_at_ms INTEGER NOT NULL,
    headers TEXT NOT NULL,
    content_type TEXT,
    body BLOB NOT NULL,
    sender_token_id TEXT,
    auth_method TEXT,
    host TEXT,
    repo TEXT
);
CREATE TABLE IF NOT EXISTS tokens (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('sender', 'consumer')),
    name TEXT NOT NULL,
    description TEXT,
    -- Sender values, which signature checks need; consumer values only in
    -- insecure reveal mode.
    value TEXT,
    fingerprint TEXT NOT NULL UNIQUE,
    prefix TEXT NOT NULL,
    is_default INTEGER NOT NULL DEFAULT 0,
    created_at_ms INTEGER NOT NULL,
    last_used_at_ms INTEGER,
    revoked_at_ms INTEGER
);
";

/// Columns added since the first release, added in place to older databases.
/// Older databases also keep an unused `signature_valid` column.
const ADDED_EVENT_COLUMNS: &[(&str, &str)] = &[
    ("sender_token_id", "TEXT"),
    ("auth_method", "TEXT"),
    ("host", "TEXT"),
    ("repo", "TEXT"),
];

/// `PRAGMA user_version` once host and repo have been filled in for events
/// stored before they existed.
const ORIGIN_BACKFILLED: i64 = 1;

const INDEXES: &str = "
CREATE UNIQUE INDEX IF NOT EXISTS events_channel_delivery
    ON events (channel, delivery_id) WHERE delivery_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS events_channel_seq ON events (channel, seq);
CREATE INDEX IF NOT EXISTS events_received_at ON events (received_at_ms);
CREATE INDEX IF NOT EXISTS tokens_kind ON tokens (kind, created_at_ms);
CREATE INDEX IF NOT EXISTS events_host_seq ON events (host, seq);
CREATE INDEX IF NOT EXISTS events_repo_seq ON events (repo, seq);
";

const EVENT_COLUMNS: &str = "e.seq, e.channel, e.source, e.delivery_id, e.event, \
    e.received_at_ms, e.headers, e.content_type, e.body, e.sender_token_id, e.auth_method, \
    e.host, e.repo, t.name";
const EVENT_FROM: &str = "events e LEFT JOIN tokens t ON t.id = e.sender_token_id";

const TOKEN_COLUMNS: &str = "id, kind, name, description, prefix, is_default, created_at_ms, \
    last_used_at_ms, revoked_at_ms, value IS NOT NULL";

impl SqliteStore {
    pub fn open(path: &Path) -> StoreResult<Self> {
        Self::init(Connection::open(path)?)
    }

    pub fn open_in_memory() -> StoreResult<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> StoreResult<Self> {
        // A delivery is acknowledged only after its commit is on disk, so
        // keep FULL synchronous mode even with WAL. The image has no /tmp.
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = FULL;
             PRAGMA temp_store = MEMORY;
             PRAGMA busy_timeout = 5000;",
        )?;
        conn.execute_batch(TABLES)?;
        let columns = conn
            .prepare("PRAGMA table_info(events)")?
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for (name, kind) in ADDED_EVENT_COLUMNS {
            if !columns.iter().any(|c| c == name) {
                conn.execute_batch(&format!("ALTER TABLE events ADD COLUMN {name} {kind}"))?;
            }
        }
        conn.execute_batch(INDEXES)?;
        backfill_origins(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
            keep_consumer_values: false,
        })
    }

    /// Keep consumer token values from now on, for insecure reveal mode.
    pub fn keep_consumer_values(mut self, keep: bool) -> Self {
        self.keep_consumer_values = keep;
        self
    }

    /// The value to store for a token: always for senders, and for
    /// consumers only when they are kept.
    fn stored_value<'a>(&self, kind: TokenKind, value: &'a str) -> Option<&'a str> {
        (kind == TokenKind::Sender || self.keep_consumer_values).then_some(value)
    }

    fn conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        // A panic while holding the lock leaves SQLite itself consistent.
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn query_events(&self, sql: &str, values: Vec<SqlValue>) -> StoreResult<Vec<Event>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(sql)?;
        let rows = stmt
            .query_map(params_from_iter(values), row_to_event)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        decode(rows)
    }
}

fn row_to_event(row: &Row<'_>) -> rusqlite::Result<(Event, String)> {
    let headers: String = row.get(6)?;
    let event = Event {
        seq: row.get(0)?,
        data: NewEvent {
            channel: row.get(1)?,
            source: row.get(2)?,
            delivery_id: row.get(3)?,
            event: row.get(4)?,
            received_at_ms: row.get(5)?,
            headers: Vec::new(),
            content_type: row.get(7)?,
            body: row.get(8)?,
            sender_token_id: row.get(9)?,
            auth_method: row.get(10)?,
            host: row.get(11)?,
            repo: row.get(12)?,
        },
        sender_name: row.get(13)?,
    };
    Ok((event, headers))
}

fn decode(rows: Vec<(Event, String)>) -> StoreResult<Vec<Event>> {
    rows.into_iter()
        .map(|(mut event, headers)| {
            event.data.headers = serde_json::from_str(&headers)?;
            Ok(event)
        })
        .collect()
}

/// `WHERE` clauses for `filter`, appended to `clauses` with their values.
fn filter_clauses(filter: &EventFilter, clauses: &mut Vec<String>, values: &mut Vec<SqlValue>) {
    for (column, wanted) in [
        ("e.channel", &filter.channels),
        ("e.source", &filter.sources),
        ("e.event", &filter.events),
        ("e.sender_token_id", &filter.senders),
        ("e.host", &filter.hosts),
    ] {
        if wanted.is_empty() {
            continue;
        }
        let marks = vec!["?"; wanted.len()].join(", ");
        clauses.push(format!("{column} IN ({marks})"));
        values.extend(wanted.iter().cloned().map(SqlValue::Text));
    }
    if !filter.repos.is_empty() {
        // Exact names, or prefixes for values ending in `*`.
        let mut any = Vec::new();
        for repo in &filter.repos {
            match repo.strip_suffix('*') {
                Some(prefix) => {
                    any.push("e.repo LIKE ? ESCAPE '\\'".to_string());
                    values.push(SqlValue::Text(format!("{}%", escape_like(prefix))));
                }
                None => {
                    any.push("e.repo = ?".to_string());
                    values.push(SqlValue::Text(repo.clone()));
                }
            }
        }
        clauses.push(format!("({})", any.join(" OR ")));
    }
}

fn escape_like(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        if matches!(c, '%' | '_' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Fill in host and repo for events stored before those columns existed.
/// Runs once per database.
fn backfill_origins(conn: &Connection) -> StoreResult<()> {
    let version: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version >= ORIGIN_BACKFILLED {
        return Ok(());
    }
    let rows = conn
        .prepare("SELECT seq, source, body FROM events WHERE host IS NULL AND repo IS NULL")?
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let tx = conn.unchecked_transaction()?;
    for (seq, source, body) in rows {
        let origin = locate(&source, &body);
        if origin.host.is_some() || origin.repo.is_some() {
            tx.execute(
                "UPDATE events SET host = ?1, repo = ?2 WHERE seq = ?3",
                params![origin.host, origin.repo, seq],
            )?;
        }
    }
    tx.execute_batch(&format!("PRAGMA user_version = {ORIGIN_BACKFILLED}"))?;
    tx.commit()?;
    Ok(())
}

fn row_to_token(row: &Row<'_>) -> rusqlite::Result<Token> {
    let kind: String = row.get(1)?;
    Ok(Token {
        id: row.get(0)?,
        kind: TokenKind::parse(&kind).unwrap_or(TokenKind::Consumer),
        name: row.get(2)?,
        description: row.get(3)?,
        prefix: row.get(4)?,
        is_default: row.get(5)?,
        created_at_ms: row.get(6)?,
        last_used_at_ms: row.get(7)?,
        revoked_at_ms: row.get(8)?,
        value_stored: row.get(9)?,
    })
}

fn token_by(conn: &Connection, column: &str, value: &str) -> StoreResult<Option<Token>> {
    Ok(conn
        .query_row(
            &format!("SELECT {TOKEN_COLUMNS} FROM tokens WHERE {column} = ?1"),
            params![value],
            row_to_token,
        )
        .optional()?)
}

fn insert_token(
    conn: &Connection,
    token: &NewToken,
    stored: Option<&str>,
    now_ms: i64,
) -> StoreResult<Token> {
    let id = new_id()?;
    if token.is_default {
        conn.execute(
            "UPDATE tokens SET is_default = 0 WHERE kind = ?1",
            params![token.kind.as_str()],
        )?;
    }
    conn.execute(
        "INSERT INTO tokens (id, kind, name, description, value, fingerprint, prefix,
                             is_default, created_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            id,
            token.kind.as_str(),
            token.name,
            token.description,
            stored,
            fingerprint(&token.value),
            display_prefix(&token.value),
            token.is_default,
            now_ms,
        ],
    )?;
    token_by(conn, "id", &id)?.ok_or_else(|| StoreError::new("token vanished after insert"))
}

impl EventStore for SqliteStore {
    fn insert(&self, e: &NewEvent) -> StoreResult<Inserted> {
        let conn = self.conn();
        // Look the delivery up first, under the connection lock: an insert
        // that hits the unique index still consumes an AUTOINCREMENT value,
        // which would leave gaps in the sequence.
        if e.delivery_id.is_some() {
            let existing = conn
                .query_row(
                    "SELECT seq FROM events WHERE channel = ?1 AND delivery_id = ?2",
                    params![e.channel, e.delivery_id],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(seq) = existing {
                return Ok(Inserted::Duplicate(seq));
            }
        }
        conn.execute(
            "INSERT INTO events (channel, source, delivery_id, event, received_at_ms, headers,
                                 content_type, body, sender_token_id, auth_method, host, repo)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                e.channel,
                e.source,
                e.delivery_id,
                e.event,
                e.received_at_ms,
                serde_json::to_string(&e.headers)?,
                e.content_type,
                e.body,
                e.sender_token_id,
                e.auth_method,
                e.host,
                e.repo,
            ],
        )?;
        Ok(Inserted::New(conn.last_insert_rowid()))
    }

    fn list(&self, filter: &EventFilter, after: i64, limit: usize) -> StoreResult<Vec<Event>> {
        let mut clauses = vec!["e.seq > ?".to_string()];
        let mut values = vec![SqlValue::Integer(after)];
        filter_clauses(filter, &mut clauses, &mut values);
        values.push(SqlValue::Integer(limit as i64));
        self.query_events(
            &format!(
                "SELECT {EVENT_COLUMNS} FROM {EVENT_FROM} WHERE {} ORDER BY e.seq LIMIT ?",
                clauses.join(" AND ")
            ),
            values,
        )
    }

    fn list_recent(
        &self,
        filter: &EventFilter,
        before: Option<i64>,
        limit: usize,
    ) -> StoreResult<Vec<Event>> {
        let mut clauses = vec!["e.seq < ?".to_string()];
        let mut values = vec![SqlValue::Integer(before.unwrap_or(i64::MAX))];
        filter_clauses(filter, &mut clauses, &mut values);
        values.push(SqlValue::Integer(limit as i64));
        self.query_events(
            &format!(
                "SELECT {EVENT_COLUMNS} FROM {EVENT_FROM} WHERE {} ORDER BY e.seq DESC LIMIT ?",
                clauses.join(" AND ")
            ),
            values,
        )
    }

    fn get(&self, seq: i64) -> StoreResult<Option<Event>> {
        Ok(self
            .query_events(
                &format!("SELECT {EVENT_COLUMNS} FROM {EVENT_FROM} WHERE e.seq = ?"),
                vec![SqlValue::Integer(seq)],
            )?
            .pop())
    }

    fn delete(&self, channel: Option<&str>) -> StoreResult<u64> {
        let changed = self.conn().execute(
            "DELETE FROM events WHERE ?1 IS NULL OR channel = ?1",
            params![channel],
        )?;
        Ok(changed as u64)
    }

    fn channels(&self) -> StoreResult<Vec<ChannelSummary>> {
        let conn = self.conn();
        let mut stmt = conn.prepare_cached(
            "SELECT channel, COUNT(*), MAX(seq), MAX(received_at_ms)
             FROM events GROUP BY channel ORDER BY channel",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok(ChannelSummary {
                    channel: row.get(0)?,
                    count: row.get::<_, i64>(1)? as u64,
                    latest_seq: row.get(2)?,
                    latest_received_at_ms: row.get(3)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    fn facets(&self) -> StoreResult<Facets> {
        let conn = self.conn();
        let (total, latest_seq) = conn.query_row(
            "SELECT COUNT(*), COALESCE(MAX(seq), 0) FROM events",
            [],
            |row| Ok((row.get::<_, i64>(0)? as u64, row.get(1)?)),
        )?;
        let counts = |sql: &str| -> StoreResult<Vec<(String, u64)>> {
            let mut stmt = conn.prepare_cached(sql)?;
            let rows = stmt
                .query_map([], |row| Ok((row.get(0)?, row.get::<_, i64>(1)? as u64)))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        };
        Ok(Facets {
            total,
            latest_seq,
            sources: counts(
                "SELECT source, COUNT(*) FROM events GROUP BY source ORDER BY COUNT(*) DESC",
            )?,
            events: counts(
                "SELECT event, COUNT(*) FROM events WHERE event IS NOT NULL
                 GROUP BY event ORDER BY COUNT(*) DESC LIMIT 200",
            )?,
            hosts: counts(
                "SELECT host, COUNT(*) FROM events WHERE host IS NOT NULL
                 GROUP BY host ORDER BY COUNT(*) DESC LIMIT 200",
            )?,
            repos: counts(
                "SELECT repo, COUNT(*) FROM events WHERE repo IS NOT NULL
                 GROUP BY repo ORDER BY COUNT(*) DESC LIMIT 200",
            )?,
        })
    }

    fn trim(&self, older_than_ms: Option<i64>, keep_latest: Option<u64>) -> StoreResult<u64> {
        let conn = self.conn();
        let mut deleted = 0;
        if let Some(cutoff) = older_than_ms {
            deleted += conn.execute(
                "DELETE FROM events WHERE received_at_ms < ?1",
                params![cutoff],
            )?;
        }
        if let Some(keep) = keep_latest {
            deleted += conn.execute(
                "DELETE FROM events WHERE seq <=
                     (SELECT seq FROM events ORDER BY seq DESC LIMIT 1 OFFSET ?1)",
                params![keep as i64],
            )?;
        }
        Ok(deleted as u64)
    }
}

impl TokenStore for SqliteStore {
    fn create_token(&self, token: &NewToken, now_ms: i64) -> StoreResult<Token> {
        let conn = self.conn();
        insert_token(
            &conn,
            token,
            self.stored_value(token.kind, &token.value),
            now_ms,
        )
    }

    fn list_tokens(&self, kind: Option<TokenKind>) -> StoreResult<Vec<Token>> {
        let conn = self.conn();
        let mut stmt = conn.prepare_cached(&format!(
            "SELECT {TOKEN_COLUMNS} FROM tokens WHERE ?1 IS NULL OR kind = ?1
             ORDER BY revoked_at_ms IS NOT NULL, is_default DESC, created_at_ms"
        ))?;
        let rows = stmt
            .query_map(params![kind.map(TokenKind::as_str)], row_to_token)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    fn get_token(&self, id: &str) -> StoreResult<Option<Token>> {
        token_by(&self.conn(), "id", id)
    }

    fn rotate_token(&self, id: &str, value: &str) -> StoreResult<Option<Token>> {
        let conn = self.conn();
        let Some(token) = token_by(&conn, "id", id)? else {
            return Ok(None);
        };
        if token.revoked_at_ms.is_some() {
            return Ok(None);
        }
        conn.execute(
            "UPDATE tokens SET value = ?1, fingerprint = ?2, prefix = ?3 WHERE id = ?4",
            params![
                self.stored_value(token.kind, value),
                fingerprint(value),
                display_prefix(value),
                id
            ],
        )?;
        token_by(&conn, "id", id)
    }

    fn revoke_token(&self, id: &str, now_ms: i64) -> StoreResult<Option<Token>> {
        let conn = self.conn();
        // A revoked token's value is not kept: nothing may verify with it,
        // and nobody needs to see it.
        conn.execute(
            "UPDATE tokens SET revoked_at_ms = COALESCE(revoked_at_ms, ?1), is_default = 0,
                               value = NULL
             WHERE id = ?2",
            params![now_ms, id],
        )?;
        token_by(&conn, "id", id)
    }

    fn sender_keys(&self) -> StoreResult<Vec<SenderKey>> {
        let conn = self.conn();
        let mut stmt = conn.prepare_cached(
            "SELECT id, value FROM tokens
             WHERE kind = 'sender' AND revoked_at_ms IS NULL AND value IS NOT NULL",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok(SenderKey {
                    id: row.get(0)?,
                    value: row.get(1)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    fn find_active(&self, kind: TokenKind, value: &str) -> StoreResult<Option<Token>> {
        let token = token_by(&self.conn(), "fingerprint", &fingerprint(value))?;
        Ok(token.filter(|t| t.kind == kind && t.revoked_at_ms.is_none()))
    }

    fn touch_token(&self, id: &str, now_ms: i64) -> StoreResult<()> {
        self.conn().execute(
            "UPDATE tokens SET last_used_at_ms = ?1
             WHERE id = ?2 AND (last_used_at_ms IS NULL OR last_used_at_ms < ?1 - 60000)",
            params![now_ms, id],
        )?;
        Ok(())
    }

    fn ensure_default(
        &self,
        kind: TokenKind,
        value: &str,
        name: &str,
        now_ms: i64,
    ) -> StoreResult<DefaultToken> {
        let conn = self.conn();
        if let Some(token) = token_by(&conn, "fingerprint", &fingerprint(value))? {
            if token.kind != kind {
                return Err(StoreError::new(format!(
                    "the default {kind} token's value belongs to a {} token",
                    token.kind
                )));
            }
            if token.revoked_at_ms.is_some() {
                return Ok(DefaultToken::Revoked(token));
            }
            conn.execute(
                "UPDATE tokens SET is_default = (id = ?1) WHERE kind = ?2",
                params![token.id, kind.as_str()],
            )?;
            // Backfill a value kept only since reveal mode was turned on.
            conn.execute(
                "UPDATE tokens SET value = ?1 WHERE id = ?2 AND value IS NULL",
                params![self.stored_value(kind, value), token.id],
            )?;
            let token = token_by(&conn, "id", &token.id)?
                .ok_or_else(|| StoreError::new("token vanished"))?;
            return Ok(DefaultToken::Existing(token));
        }
        let token = insert_token(
            &conn,
            &NewToken {
                kind,
                name: name.to_string(),
                description: Some(format!("Default {kind} token, from deployment secrets")),
                value: value.to_string(),
                is_default: true,
            },
            self.stored_value(kind, value),
            now_ms,
        )?;
        Ok(DefaultToken::Created(token))
    }

    fn token_value(&self, id: &str) -> StoreResult<Option<String>> {
        Ok(self
            .conn()
            .query_row(
                "SELECT value FROM tokens WHERE id = ?1 AND revoked_at_ms IS NULL",
                params![id],
                |row| row.get(0),
            )
            .optional()?
            .flatten())
    }

    fn forget_consumer_values(&self) -> StoreResult<u64> {
        let changed = self.conn().execute(
            "UPDATE tokens SET value = NULL WHERE kind = 'consumer' AND value IS NOT NULL",
            [],
        )?;
        Ok(changed as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(channel: &str, delivery_id: Option<&str>, received_at_ms: i64) -> NewEvent {
        NewEvent {
            channel: channel.into(),
            source: "generic".into(),
            delivery_id: delivery_id.map(Into::into),
            event: None,
            received_at_ms,
            headers: vec![("x-a".into(), "1".into()), ("x-a".into(), "2".into())],
            content_type: Some("application/octet-stream".into()),
            body: vec![0, 159, 146, 150, 255],
            sender_token_id: None,
            auth_method: None,
            host: None,
            repo: None,
        }
    }

    fn all() -> EventFilter {
        EventFilter::default()
    }

    fn channel(name: &str) -> EventFilter {
        EventFilter {
            channels: vec![name.into()],
            ..EventFilter::default()
        }
    }

    #[test]
    fn round_trips_bytes_and_duplicate_headers() {
        let store = SqliteStore::open_in_memory().unwrap();
        let new = event("a", None, 1);
        let Inserted::New(seq) = store.insert(&new).unwrap() else {
            panic!("expected a new event");
        };
        assert_eq!(store.get(seq).unwrap().unwrap().data, new);
        assert_eq!(store.get(seq + 1).unwrap(), None);
    }

    #[test]
    fn duplicate_delivery_id_is_per_channel() {
        let store = SqliteStore::open_in_memory().unwrap();
        let first = store.insert(&event("a", Some("d1"), 1)).unwrap();
        assert_eq!(
            store.insert(&event("a", Some("d1"), 2)).unwrap(),
            match first {
                Inserted::New(seq) => Inserted::Duplicate(seq),
                other => panic!("{other:?}"),
            }
        );
        // A duplicate leaves no gap in the sequence.
        assert_eq!(
            store.insert(&event("b", Some("d1"), 3)).unwrap(),
            Inserted::New(2)
        );
        // Events without a delivery ID never collide.
        store.insert(&event("a", None, 4)).unwrap();
        store.insert(&event("a", None, 5)).unwrap();
        assert_eq!(store.list(&channel("a"), 0, 10).unwrap().len(), 3);
    }

    #[test]
    fn filters_combine_and_recent_lists_newest_first() {
        let store = SqliteStore::open_in_memory().unwrap();
        for (ch, source, ev) in [
            ("gh", "github", "issues"),
            ("gh", "github", "pull_request"),
            ("jira", "jira", "jira:issue_created"),
            ("gh", "github", "issues"),
        ] {
            let mut e = event(ch, None, 1);
            e.source = source.into();
            e.event = Some(ev.into());
            store.insert(&e).unwrap();
        }
        let seqs = |events: Vec<Event>| events.iter().map(|e| e.seq).collect::<Vec<_>>();
        let issues = EventFilter {
            sources: vec!["github".into()],
            events: vec!["issues".into()],
            ..all()
        };
        assert_eq!(seqs(store.list(&issues, 0, 10).unwrap()), vec![1, 4]);
        let either = EventFilter {
            events: vec!["pull_request".into(), "jira:issue_created".into()],
            ..all()
        };
        assert_eq!(seqs(store.list(&either, 0, 10).unwrap()), vec![2, 3]);
        assert_eq!(
            seqs(store.list_recent(&all(), None, 2).unwrap()),
            vec![4, 3]
        );
        assert_eq!(
            seqs(store.list_recent(&all(), Some(3), 10).unwrap()),
            vec![2, 1]
        );

        let facets = store.facets().unwrap();
        assert_eq!((facets.total, facets.latest_seq), (4, 4));
        assert_eq!(facets.sources[0], ("github".into(), 3));
        assert_eq!(facets.events[0], ("issues".into(), 2));
    }

    #[test]
    fn host_and_repo_filters_with_prefixes() {
        let store = SqliteStore::open_in_memory().unwrap();
        for (host, repo) in [
            ("github.local", "org/a"),
            ("github.local", "org/b"),
            ("github.com", "org/a"),
            ("github.local", "other/c"),
            ("github.local", "org_x/d"),
        ] {
            let mut e = event("gh", None, 1);
            e.host = Some(host.into());
            e.repo = Some(repo.into());
            store.insert(&e).unwrap();
        }
        let seqs = |filter: EventFilter| {
            store
                .list(&filter, 0, 10)
                .unwrap()
                .iter()
                .map(|e| e.seq)
                .collect::<Vec<_>>()
        };
        let by = |hosts: &[&str], repos: &[&str]| EventFilter {
            hosts: hosts.iter().map(|s| s.to_string()).collect(),
            repos: repos.iter().map(|s| s.to_string()).collect(),
            ..all()
        };
        assert_eq!(seqs(by(&["github.local"], &[])), vec![1, 2, 4, 5]);
        assert_eq!(seqs(by(&[], &["org/a"])), vec![1, 3]);
        assert_eq!(seqs(by(&["github.local"], &["org/a"])), vec![1]);
        assert_eq!(seqs(by(&[], &["org/*"])), vec![1, 2, 3]);
        // `_` is literal in a prefix, not a LIKE wildcard.
        assert_eq!(seqs(by(&[], &["org_*"])), vec![5]);
        assert_eq!(seqs(by(&[], &["org/a", "other/*"])), vec![1, 3, 4]);
        assert_eq!(seqs(by(&[], &["*"])), vec![1, 2, 3, 4, 5]);
        let facets = store.facets().unwrap();
        assert_eq!(facets.hosts[0], ("github.local".into(), 4));
        assert_eq!(facets.repos[0], ("org/a".into(), 2));
    }

    #[test]
    fn trim_by_age_then_count() {
        let store = SqliteStore::open_in_memory().unwrap();
        for at in 1..=10 {
            store.insert(&event("a", None, at)).unwrap();
        }
        assert_eq!(store.trim(Some(4), None).unwrap(), 3);
        assert_eq!(store.trim(None, Some(5)).unwrap(), 2);
        let left: Vec<i64> = store
            .list(&all(), 0, 100)
            .unwrap()
            .iter()
            .map(|e| e.data.received_at_ms)
            .collect();
        assert_eq!(left, vec![6, 7, 8, 9, 10]);
        assert_eq!(store.trim(Some(0), Some(5)).unwrap(), 0);
    }

    #[test]
    fn sequence_numbers_are_not_reused_after_reset() {
        let store = SqliteStore::open_in_memory().unwrap();
        let Inserted::New(first) = store.insert(&event("a", None, 1)).unwrap() else {
            panic!();
        };
        assert_eq!(store.delete(None).unwrap(), 1);
        let Inserted::New(second) = store.insert(&event("a", None, 2)).unwrap() else {
            panic!();
        };
        assert!(second > first);
    }

    #[test]
    fn channel_summaries() {
        let store = SqliteStore::open_in_memory().unwrap();
        store.insert(&event("b", None, 5)).unwrap();
        store.insert(&event("a", None, 6)).unwrap();
        store.insert(&event("b", None, 7)).unwrap();
        let summary = store.channels().unwrap();
        assert_eq!(summary.len(), 2);
        assert_eq!(summary[0].channel, "a");
        assert_eq!(summary[1].count, 2);
        assert_eq!(summary[1].latest_seq, 3);
        assert_eq!(summary[1].latest_received_at_ms, 7);
        assert_eq!(store.delete(Some("b")).unwrap(), 2);
        assert_eq!(store.channels().unwrap().len(), 1);
    }

    fn new_token(kind: TokenKind, value: &str) -> NewToken {
        NewToken {
            kind,
            name: format!("{kind} token"),
            description: None,
            value: value.into(),
            is_default: false,
        }
    }

    #[test]
    fn sender_values_are_kept_and_consumer_values_are_not() {
        let store = SqliteStore::open_in_memory().unwrap();
        let sender = store
            .create_token(&new_token(TokenKind::Sender, "whs_secret-value"), 1)
            .unwrap();
        let consumer = store
            .create_token(&new_token(TokenKind::Consumer, "whc_reader-value"), 1)
            .unwrap();
        assert_eq!(sender.prefix, "whs_secret-v");
        let keys = store.sender_keys().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(
            (keys[0].id.as_str(), keys[0].value.as_str()),
            (sender.id.as_str(), "whs_secret-value")
        );
        let stored: Option<String> = store
            .conn()
            .query_row(
                "SELECT value FROM tokens WHERE id = ?1",
                [&consumer.id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(stored, None);

        assert_eq!(
            store
                .find_active(TokenKind::Consumer, "whc_reader-value")
                .unwrap(),
            Some(consumer.clone())
        );
        // A value only authenticates as its own kind.
        assert_eq!(
            store
                .find_active(TokenKind::Sender, "whc_reader-value")
                .unwrap(),
            None
        );
    }

    #[test]
    fn reveal_mode_keeps_consumer_values_until_turned_off() {
        let store = SqliteStore::open_in_memory()
            .unwrap()
            .keep_consumer_values(true);
        let consumer = store
            .create_token(&new_token(TokenKind::Consumer, "whc_kept"), 1)
            .unwrap();
        let sender = store
            .create_token(&new_token(TokenKind::Sender, "whs_kept"), 1)
            .unwrap();
        assert!(consumer.value_stored && sender.value_stored);
        assert_eq!(
            store.token_value(&consumer.id).unwrap().as_deref(),
            Some("whc_kept")
        );
        assert_eq!(
            store.token_value(&sender.id).unwrap().as_deref(),
            Some("whs_kept")
        );
        assert_eq!(store.token_value("tok_missing").unwrap(), None);

        // Turning reveal mode off forgets consumer values, never sender ones.
        assert_eq!(store.forget_consumer_values().unwrap(), 1);
        assert_eq!(store.token_value(&consumer.id).unwrap(), None);
        assert!(!store.get_token(&consumer.id).unwrap().unwrap().value_stored);
        assert_eq!(
            store.token_value(&sender.id).unwrap().as_deref(),
            Some("whs_kept")
        );
        // The token still authenticates by fingerprint.
        assert!(
            store
                .find_active(TokenKind::Consumer, "whc_kept")
                .unwrap()
                .is_some()
        );

        // A revoked token's value is never revealed.
        store.revoke_token(&sender.id, 2).unwrap();
        assert_eq!(store.token_value(&sender.id).unwrap(), None);
    }

    #[test]
    fn reveal_mode_backfills_the_default_consumer_value() {
        let store = SqliteStore::open_in_memory().unwrap();
        let DefaultToken::Created(token) = store
            .ensure_default(TokenKind::Consumer, "whc_default", "default-consumer", 1)
            .unwrap()
        else {
            panic!("expected a new default");
        };
        assert!(!token.value_stored);
        // A restart with reveal mode on.
        let store = store.keep_consumer_values(true);
        let DefaultToken::Existing(token) = store
            .ensure_default(TokenKind::Consumer, "whc_default", "default-consumer", 2)
            .unwrap()
        else {
            panic!("expected the existing default");
        };
        assert!(token.value_stored);
        assert_eq!(
            store.token_value(&token.id).unwrap().as_deref(),
            Some("whc_default")
        );
    }

    #[test]
    fn rotate_and_revoke() {
        let store = SqliteStore::open_in_memory().unwrap();
        let token = store
            .create_token(&new_token(TokenKind::Sender, "whs_old"), 1)
            .unwrap();
        let rotated = store.rotate_token(&token.id, "whs_new").unwrap().unwrap();
        assert_eq!(rotated.id, token.id);
        assert_eq!(
            store.find_active(TokenKind::Sender, "whs_old").unwrap(),
            None
        );
        assert!(
            store
                .find_active(TokenKind::Sender, "whs_new")
                .unwrap()
                .is_some()
        );

        let revoked = store.revoke_token(&token.id, 5).unwrap().unwrap();
        assert_eq!(revoked.revoked_at_ms, Some(5));
        assert!(store.sender_keys().unwrap().is_empty());
        assert_eq!(
            store.find_active(TokenKind::Sender, "whs_new").unwrap(),
            None
        );
        assert_eq!(store.rotate_token(&token.id, "whs_again").unwrap(), None);
        assert_eq!(store.revoke_token("tok_missing", 5).unwrap(), None);
    }

    #[test]
    fn ensure_default_creates_reuses_and_respects_revocation() {
        let store = SqliteStore::open_in_memory().unwrap();
        let DefaultToken::Created(first) = store
            .ensure_default(TokenKind::Sender, "whs_default-1", "default-sender", 1)
            .unwrap()
        else {
            panic!("expected a new default");
        };
        assert!(first.is_default);
        // A restart with the same value finds the same token.
        assert_eq!(
            store
                .ensure_default(TokenKind::Sender, "whs_default-1", "default-sender", 2)
                .unwrap(),
            DefaultToken::Existing(first.clone())
        );
        // A new value becomes the default; the old token stays active.
        let DefaultToken::Created(second) = store
            .ensure_default(TokenKind::Sender, "whs_default-2", "default-sender", 3)
            .unwrap()
        else {
            panic!("expected a new default");
        };
        let old = store.get_token(&first.id).unwrap().unwrap();
        assert!(!old.is_default && old.revoked_at_ms.is_none());
        assert!(second.is_default);

        store.revoke_token(&second.id, 4).unwrap();
        assert!(matches!(
            store
                .ensure_default(TokenKind::Sender, "whs_default-2", "default-sender", 5)
                .unwrap(),
            DefaultToken::Revoked(_)
        ));
        assert!(
            store
                .ensure_default(TokenKind::Consumer, "whs_default-1", "default-consumer", 6)
                .is_err()
        );
    }

    #[test]
    fn upgrades_a_first_release_database() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("events.sqlite");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE events (
                     seq INTEGER PRIMARY KEY AUTOINCREMENT, channel TEXT NOT NULL,
                     source TEXT NOT NULL, delivery_id TEXT, event TEXT,
                     received_at_ms INTEGER NOT NULL, headers TEXT NOT NULL,
                     content_type TEXT, body BLOB NOT NULL, signature_valid INTEGER);
                 INSERT INTO events (channel, source, received_at_ms, headers, body, signature_valid)
                     VALUES ('old', 'github', 1, '[]', x'7b7d', 1);
                 INSERT INTO events (channel, source, received_at_ms, headers, body)
                     VALUES ('old', 'github', 2, '[]',
                             CAST('{\"repository\":{\"full_name\":\"org/r\",\"html_url\":\"https://github.local/org/r\"}}' AS BLOB));",
            )
            .unwrap();
        }
        let store = SqliteStore::open(&path).unwrap();
        let old = store.get(1).unwrap().unwrap();
        assert_eq!(old.data.channel, "old");
        assert_eq!(old.data.sender_token_id, None);
        // Events stored before host and repo existed are located on upgrade.
        let located = store.get(2).unwrap().unwrap();
        assert_eq!(located.data.host.as_deref(), Some("github.local"));
        assert_eq!(located.data.repo.as_deref(), Some("org/r"));
        store.insert(&event("new", None, 3)).unwrap();
        assert_eq!(store.list(&all(), 0, 10).unwrap().len(), 3);
        drop(store);
        // The backfill runs once.
        let conn = Connection::open(&path).unwrap();
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, ORIGIN_BACKFILLED);
    }
}
