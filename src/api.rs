//! Public listener: senders `POST /hooks/{channel}` with a sender token;
//! consumers read `/events` with a consumer token.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, RawQuery, Request, State};
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{Map, Value, json};
use tokio::sync::watch;
use tokio::time::Instant;

use crate::config::Config;
use crate::store::{Event, EventFilter, EventStore, Inserted, NewEvent, StoreError, StoreResult};
use crate::tokens::{TokenKind, TokenStore};
use crate::verify::{classify, header, hmac_matches, locate, signatures};

pub const DEFAULT_LIMIT: usize = 100;
pub const MAX_LIMIT: usize = 1000;

/// Header values never stored, because they are credentials. GitLab sends
/// the sender token itself as `X-Gitlab-Token`.
const REDACTED_HEADERS: &[&str] = &["x-gitlab-token", "authorization", "cookie"];

#[derive(Clone, Debug)]
pub struct Settings {
    pub max_body_bytes: usize,
    pub max_wait: Duration,
}

impl From<&Config> for Settings {
    fn from(config: &Config) -> Self {
        Self {
            max_body_bytes: config.max_body_bytes,
            max_wait: config.max_wait,
        }
    }
}

#[derive(Clone)]
pub struct AppState {
    events: Arc<dyn EventStore>,
    tokens: Arc<dyn TokenStore>,
    /// The newest committed `seq`; long-polls wait for it to change.
    latest: Arc<watch::Sender<i64>>,
    shutdown: watch::Receiver<bool>,
    settings: Arc<Settings>,
}

impl AppState {
    pub fn new(
        events: Arc<dyn EventStore>,
        tokens: Arc<dyn TokenStore>,
        settings: Settings,
        shutdown: watch::Receiver<bool>,
    ) -> Self {
        Self {
            events,
            tokens,
            latest: Arc::new(watch::channel(0).0),
            shutdown,
            settings: Arc::new(settings),
        }
    }
}

pub fn router(state: AppState) -> Router {
    let hooks = Router::new()
        .route("/hooks/{channel}", post(receive))
        .layer(DefaultBodyLimit::max(state.settings.max_body_bytes));
    let consumers = Router::new()
        .route("/events", get(list_events))
        .route("/events/{seq}", get(get_event))
        .route("/events/{seq}/raw", get(get_raw))
        .route("/channels", get(list_channels))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_consumer,
        ));
    Router::new()
        .merge(hooks)
        .merge(consumers)
        .route("/", get(index))
        .route("/healthz", get(healthz))
        .with_state(state)
}

/// Letters, digits, `-`, `_` and `.`, not starting with `.`; at most 64.
pub fn valid_channel(channel: &str) -> bool {
    (1..=64).contains(&channel.len())
        && !channel.starts_with('.')
        && channel
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

pub(crate) fn error(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({ "message": message }))).into_response()
}

pub(crate) fn store_error(e: StoreError) -> Response {
    eprintln!("store error: {e}");
    error(StatusCode::INTERNAL_SERVER_ERROR, "storage error")
}

pub(crate) async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> StoreResult<T> + Send + 'static,
) -> StoreResult<T> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| StoreError::new(e.to_string()))?
}

pub(crate) fn now_ms() -> i64 {
    Utc::now().timestamp_millis()
}

pub(crate) fn bearer(headers: &HeaderMap) -> Option<&str> {
    let (scheme, value) = header(headers, AUTHORIZATION.as_str())?.split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("bearer")
        .then(|| value.trim())
        .filter(|v| !v.is_empty())
}

/// Query parameters in order, percent-decoded.
pub(crate) fn query_pairs(raw: Option<&str>) -> Vec<(String, String)> {
    form_urlencoded::parse(raw.unwrap_or("").as_bytes())
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

/// The filter in `channel`, `source`, `event`, `sender`, `host` and `repo`
/// parameters. Each may repeat or hold a comma-separated list; a `repo`
/// value ending in `*` matches by prefix.
pub(crate) fn event_filter(pairs: &[(String, String)]) -> EventFilter {
    let mut filter = EventFilter::default();
    for (key, value) in pairs {
        let target = match key.as_str() {
            "channel" => &mut filter.channels,
            "source" => &mut filter.sources,
            "event" => &mut filter.events,
            "sender" => &mut filter.senders,
            "host" => &mut filter.hosts,
            "repo" => &mut filter.repos,
            _ => continue,
        };
        target.extend(
            value
                .split(',')
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(str::to_string),
        );
    }
    filter
}

/// The last value of an integer parameter; `Err` describes a malformed one.
pub(crate) fn number<T: std::str::FromStr>(
    pairs: &[(String, String)],
    key: &str,
) -> Result<Option<T>, String> {
    match pairs.iter().rev().find(|(k, _)| k == key) {
        None => Ok(None),
        Some((_, v)) => v
            .parse()
            .map(Some)
            .map_err(|_| format!("{key} must be a non-negative integer")),
    }
}

async fn require_consumer(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let Some(value) = bearer(request.headers()).map(str::to_string) else {
        return error(StatusCode::UNAUTHORIZED, "a consumer token is required");
    };
    let tokens = state.tokens.clone();
    let found = blocking(move || {
        let token = tokens.find_active(TokenKind::Consumer, &value)?;
        if let Some(token) = &token {
            tokens.touch_token(&token.id, now_ms())?;
        }
        Ok(token)
    })
    .await;
    match found {
        Ok(Some(_)) => next.run(request).await,
        Ok(None) => error(
            StatusCode::UNAUTHORIZED,
            "invalid or revoked consumer token",
        ),
        Err(e) => store_error(e),
    }
}

async fn healthz() -> Response {
    Json(json!({ "status": "ok" })).into_response()
}

async fn index() -> Response {
    Json(json!({
        "service": "webhook-sink",
        "version": env!("CARGO_PKG_VERSION"),
        "endpoints": [
            "POST /hooks/{channel}   (sender token: signature, X-Gitlab-Token, Bearer or ?token=)",
            "GET /events?channel=&source=&event=&sender=&host=&repo=&after=&limit=&wait=   (consumer token)",
            "GET /events/{seq}   (consumer token)",
            "GET /events/{seq}/raw   (consumer token)",
            "GET /channels   (consumer token)",
            "GET /healthz",
        ],
    }))
    .into_response()
}

/// How a delivery identified its sender token.
#[derive(Debug, PartialEq, Eq)]
pub enum SenderAuth {
    Accepted {
        token_id: String,
        method: &'static str,
    },
    Rejected(&'static str),
}

/// Identify the sender token behind a delivery.
///
/// A delivery that carries a signature header is judged by the signature
/// alone: it must be the body signed with an active sender token. Without
/// one, the sink accepts the token itself, from `X-Gitlab-Token`,
/// `Authorization: Bearer` or the `token` query parameter, in that order.
pub fn authenticate_sender(
    tokens: &dyn TokenStore,
    headers: &HeaderMap,
    query_token: Option<&str>,
    body: &[u8],
) -> StoreResult<SenderAuth> {
    let digests = signatures(headers);
    if !digests.is_empty() {
        for key in tokens.sender_keys()? {
            if digests
                .iter()
                .any(|digest| hmac_matches(key.value.as_bytes(), body, digest))
            {
                return Ok(SenderAuth::Accepted {
                    token_id: key.id,
                    method: "hmac",
                });
            }
        }
        return Ok(SenderAuth::Rejected(
            "signature does not match any active sender token",
        ));
    }
    let presented = [
        (header(headers, "x-gitlab-token"), "gitlab-token"),
        (bearer(headers), "bearer"),
        (query_token, "query"),
    ]
    .into_iter()
    .find_map(|(value, method)| value.map(|v| (v, method)));
    let Some((value, method)) = presented else {
        return Ok(SenderAuth::Rejected(
            "a sender token is required: sign the body with it, or send it as X-Gitlab-Token, a bearer token or ?token=",
        ));
    };
    Ok(match tokens.find_active(TokenKind::Sender, value)? {
        Some(token) => SenderAuth::Accepted {
            token_id: token.id,
            method,
        },
        None => SenderAuth::Rejected("invalid or revoked sender token"),
    })
}

async fn receive(
    State(state): State<AppState>,
    Path(channel): Path<String>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !valid_channel(&channel) {
        return error(StatusCode::BAD_REQUEST, "invalid channel name");
    }
    let query_token = query_pairs(query.as_deref())
        .into_iter()
        .rev()
        .find(|(k, _)| k == "token")
        .map(|(_, v)| v);
    let auth = {
        let tokens = state.tokens.clone();
        let headers = headers.clone();
        let body = body.clone();
        blocking(move || {
            let auth =
                authenticate_sender(tokens.as_ref(), &headers, query_token.as_deref(), &body)?;
            if let SenderAuth::Accepted { token_id, .. } = &auth {
                tokens.touch_token(token_id, now_ms())?;
            }
            Ok(auth)
        })
        .await
    };
    let (token_id, method) = match auth {
        Ok(SenderAuth::Accepted { token_id, method }) => (token_id, method),
        Ok(SenderAuth::Rejected(reason)) => return error(StatusCode::UNAUTHORIZED, reason),
        Err(e) => return store_error(e),
    };
    let sender = classify(&headers, &body);
    let origin = locate(sender.source, &body);
    let new = NewEvent {
        channel,
        source: sender.source.to_string(),
        delivery_id: sender.delivery_id,
        event: sender.event,
        received_at_ms: now_ms(),
        headers: header_pairs(&headers),
        content_type: headers
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string),
        body: body.to_vec(),
        sender_token_id: Some(token_id),
        auth_method: Some(method.to_string()),
        host: origin.host,
        repo: origin.repo,
    };
    let summary = format!(
        "channel={} source={} event={} sender={} auth={}",
        new.channel,
        new.source,
        new.event.as_deref().unwrap_or("-"),
        new.sender_token_id.as_deref().unwrap_or("-"),
        method,
    );
    let events = state.events.clone();
    match blocking(move || events.insert(&new)).await {
        Ok(Inserted::New(seq)) => {
            state.latest.send_replace(seq);
            eprintln!("stored seq={seq} {summary}");
            (
                StatusCode::ACCEPTED,
                Json(json!({ "seq": seq, "duplicate": false })),
            )
                .into_response()
        }
        Ok(Inserted::Duplicate(seq)) => {
            eprintln!("duplicate of seq={seq} {summary}");
            Json(json!({ "seq": seq, "duplicate": true })).into_response()
        }
        Err(e) => store_error(e),
    }
}

fn header_pairs(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(name, value)| {
            let value = if REDACTED_HEADERS.contains(&name.as_str()) {
                "[redacted]".to_string()
            } else {
                String::from_utf8_lossy(value.as_bytes()).into_owned()
            };
            (name.as_str().to_string(), value)
        })
        .collect()
}

async fn list_events(State(state): State<AppState>, RawQuery(query): RawQuery) -> Response {
    let pairs = query_pairs(query.as_deref());
    let filter = event_filter(&pairs);
    let (after, limit, wait) = match (
        number::<i64>(&pairs, "after"),
        number::<usize>(&pairs, "limit"),
        number::<u64>(&pairs, "wait"),
    ) {
        (Ok(a), Ok(l), Ok(w)) => (a.unwrap_or(0), l, w),
        (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => {
            return error(StatusCode::BAD_REQUEST, &e);
        }
    };
    let limit = limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let wait = Duration::from_secs(wait.unwrap_or(0)).min(state.settings.max_wait);
    let deadline = Instant::now() + wait;
    // Subscribe before the first query, so an insert between the query and
    // the wait still wakes this request.
    let mut latest = state.latest.subscribe();
    let mut shutdown = state.shutdown.clone();
    let mut last_round = wait.is_zero();
    loop {
        let events = state.events.clone();
        let query_filter = filter.clone();
        let found = match blocking(move || events.list(&query_filter, after, limit)).await {
            Ok(found) => found,
            Err(e) => return store_error(e),
        };
        if !found.is_empty() || last_round || *shutdown.borrow() {
            let next_after = found.last().map_or(after, |e| e.seq);
            let found: Vec<Value> = found.iter().map(event_json).collect();
            return Json(json!({ "events": found, "next_after": next_after })).into_response();
        }
        // An insert that does not match the filter wakes this request too;
        // it then queries again and keeps waiting until the deadline.
        let woke = tokio::select! {
            _ = tokio::time::sleep_until(deadline) => false,
            changed = latest.changed() => changed.is_ok(),
            _ = shutdown.changed() => false,
        };
        last_round = !woke;
    }
}

pub(crate) async fn event_response(events: Arc<dyn EventStore>, seq: i64) -> Response {
    match blocking(move || events.get(seq)).await {
        Ok(Some(event)) => Json(event_json(&event)).into_response(),
        Ok(None) => error(StatusCode::NOT_FOUND, "no such event"),
        Err(e) => store_error(e),
    }
}

pub(crate) async fn raw_response(events: Arc<dyn EventStore>, seq: i64) -> Response {
    match blocking(move || events.get(seq)).await {
        Ok(Some(event)) => {
            let content_type = event
                .data
                .content_type
                .unwrap_or_else(|| "application/octet-stream".into());
            ([(CONTENT_TYPE, content_type)], event.data.body).into_response()
        }
        Ok(None) => error(StatusCode::NOT_FOUND, "no such event"),
        Err(e) => store_error(e),
    }
}

pub(crate) async fn channels_response(events: Arc<dyn EventStore>) -> Response {
    match blocking(move || events.channels()).await {
        Ok(channels) => {
            let channels: Vec<Value> = channels
                .into_iter()
                .map(|c| {
                    json!({
                        "channel": c.channel,
                        "count": c.count,
                        "latest_seq": c.latest_seq,
                        "latest_received_at": timestamp(c.latest_received_at_ms),
                    })
                })
                .collect();
            Json(json!({ "channels": channels })).into_response()
        }
        Err(e) => store_error(e),
    }
}

async fn get_event(State(state): State<AppState>, Path(seq): Path<i64>) -> Response {
    event_response(state.events.clone(), seq).await
}

async fn get_raw(State(state): State<AppState>, Path(seq): Path<i64>) -> Response {
    raw_response(state.events.clone(), seq).await
}

async fn list_channels(State(state): State<AppState>) -> Response {
    channels_response(state.events.clone()).await
}

pub(crate) fn timestamp(ms: i64) -> Option<String> {
    DateTime::from_timestamp_millis(ms).map(|t| t.to_rfc3339_opts(SecondsFormat::Millis, true))
}

/// The JSON form of an event. The body appears as exactly one of:
/// - `payload`, when it parses as JSON;
/// - `body`, when it is other UTF-8 text;
/// - `body_base64`, otherwise.
///
/// `/events/{seq}/raw` returns the original bytes.
pub fn event_json(event: &Event) -> Value {
    let d = &event.data;
    let mut headers = Map::new();
    for (name, value) in &d.headers {
        match headers.get_mut(name) {
            Some(Value::String(existing)) => {
                existing.push_str(", ");
                existing.push_str(value);
            }
            _ => {
                headers.insert(name.clone(), Value::String(value.clone()));
            }
        }
    }
    let sender = d.sender_token_id.as_ref().map(|id| {
        json!({
            "token_id": id,
            "name": event.sender_name,
            "method": d.auth_method,
        })
    });
    let mut out = json!({
        "seq": event.seq,
        "channel": d.channel,
        "source": d.source,
        "delivery_id": d.delivery_id,
        "event": d.event,
        "host": d.host,
        "repo": d.repo,
        "received_at": timestamp(d.received_at_ms),
        "sender": sender,
        "headers": headers,
        "content_type": d.content_type,
        "size": d.body.len(),
    });
    let (key, value) = match serde_json::from_slice::<Value>(&d.body) {
        Ok(payload) => ("payload", payload),
        Err(_) => match std::str::from_utf8(&d.body) {
            Ok(text) => ("body", Value::String(text.to_string())),
            Err(_) => (
                "body_base64",
                Value::String(base64::engine::general_purpose::STANDARD.encode(&d.body)),
            ),
        },
    };
    out[key] = value;
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_names() {
        for ok in ["github", "a", "repo.hooks", "jira_main-2", &"x".repeat(64)] {
            assert!(valid_channel(ok), "{ok}");
        }
        for bad in [
            "",
            ".",
            "..",
            ".hidden",
            "a/b",
            "a b",
            "a$",
            &"x".repeat(65),
        ] {
            assert!(!valid_channel(bad), "{bad}");
        }
    }

    #[test]
    fn filters_accept_repeats_and_commas() {
        let pairs = query_pairs(Some(
            "source=github,jira&event=issues&event=pull_request&channel=&sender=tok_1&after=5&host=github.local&repo=org/*,other/x",
        ));
        let filter = event_filter(&pairs);
        assert_eq!(filter.sources, vec!["github", "jira"]);
        assert_eq!(filter.events, vec!["issues", "pull_request"]);
        assert!(filter.channels.is_empty());
        assert_eq!(filter.senders, vec!["tok_1"]);
        assert_eq!(filter.hosts, vec!["github.local"]);
        assert_eq!(filter.repos, vec!["org/*", "other/x"]);
        assert_eq!(number::<i64>(&pairs, "after").unwrap(), Some(5));
        assert!(number::<i64>(&query_pairs(Some("after=x")), "after").is_err());
    }

    #[test]
    fn bearer_parsing() {
        let mut headers = HeaderMap::new();
        assert_eq!(bearer(&headers), None);
        headers.insert(AUTHORIZATION, "bearer  abc ".parse().unwrap());
        assert_eq!(bearer(&headers), Some("abc"));
        headers.insert(AUTHORIZATION, "Basic abc".parse().unwrap());
        assert_eq!(bearer(&headers), None);
    }
}
