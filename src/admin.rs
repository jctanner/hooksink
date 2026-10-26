//! Admin listener: the console at `/admin/` and its private API under
//! `/api/private/v1`, which requires the admin key as a bearer token.
//!
//! The admin listener is separate from the public one, so exposing
//! `/hooks` later (for example through a tunnel for real GitHub) never
//! exposes token management.

use std::sync::Arc;

use axum::extract::{Path, RawQuery, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use subtle::ConstantTimeEq;

use crate::api::{
    DEFAULT_LIMIT, MAX_LIMIT, bearer, blocking, channels_response, error, event_filter, event_json,
    event_response, now_ms, number, query_pairs, raw_response, store_error, timestamp,
    valid_channel,
};
use crate::store::EventStore;
use crate::tokens::{NewToken, Token, TokenKind, TokenStore, generate};

const API: &str = "/api/private/v1";

#[derive(Clone)]
pub struct AdminState {
    events: Arc<dyn EventStore>,
    tokens: Arc<dyn TokenStore>,
    admin_key: Arc<String>,
    /// Base URL senders and consumers use, shown in the console.
    public_url: Option<Arc<String>>,
    /// Insecure reveal mode: stored token values may be shown.
    reveal_tokens: bool,
}

impl AdminState {
    pub fn new(
        events: Arc<dyn EventStore>,
        tokens: Arc<dyn TokenStore>,
        admin_key: String,
        public_url: Option<String>,
        reveal_tokens: bool,
    ) -> Self {
        Self {
            events,
            tokens,
            admin_key: Arc::new(admin_key),
            public_url: public_url.map(|u| Arc::new(u.trim_end_matches('/').to_string())),
            reveal_tokens,
        }
    }
}

pub fn router(state: AdminState) -> Router {
    let api = Router::new()
        .route("/overview", get(overview))
        .route("/events", get(list_events).delete(reset_events))
        .route("/events/{seq}", get(get_event))
        .route("/events/{seq}/raw", get(get_raw))
        .route("/channels", get(list_channels))
        .route("/tokens", get(list_tokens).post(create_token))
        .route("/tokens/{id}/rotate", post(rotate_token))
        .route("/tokens/{id}/revoke", post(revoke_token))
        .route("/tokens/{id}/value", get(token_value))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_admin));
    Router::new()
        .nest(API, api)
        .route("/", get(|| async { Redirect::temporary("/admin/") }))
        .route("/admin", get(|| async { Redirect::temporary("/admin/") }))
        .route(
            "/admin/",
            get(|| async {
                asset(
                    "text/html; charset=utf-8",
                    include_str!("admin_ui/index.html"),
                )
            }),
        )
        .route(
            "/admin/admin.css",
            get(|| async {
                asset(
                    "text/css; charset=utf-8",
                    include_str!("admin_ui/admin.css"),
                )
            }),
        )
        .route(
            "/admin/admin.js",
            get(|| async {
                asset(
                    "text/javascript; charset=utf-8",
                    include_str!("admin_ui/admin.js"),
                )
            }),
        )
        .route(
            "/healthz",
            get(|| async { Json(json!({ "status": "ok" })) }),
        )
        .with_state(state)
}

fn asset(content_type: &'static str, body: &'static str) -> Response {
    let mut headers = HeaderMap::new();
    for (name, value) in [
        ("content-type", content_type),
        ("cache-control", "no-store"),
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "no-referrer"),
        ("x-frame-options", "DENY"),
        (
            "content-security-policy",
            "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
        ),
    ] {
        headers.insert(name, HeaderValue::from_static(value));
    }
    (headers, body).into_response()
}

async fn require_admin(State(state): State<AdminState>, request: Request, next: Next) -> Response {
    let ok = bearer(request.headers())
        .is_some_and(|key| bool::from(key.as_bytes().ct_eq(state.admin_key.as_bytes())));
    if !ok {
        return error(StatusCode::UNAUTHORIZED, "the admin key is required");
    }
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert("cache-control", HeaderValue::from_static("no-store"));
    response
}

fn token_json(token: &Token) -> Value {
    json!({
        "id": token.id,
        "kind": token.kind.as_str(),
        "name": token.name,
        "description": token.description,
        "prefix": token.prefix,
        "is_default": token.is_default,
        "status": if token.revoked_at_ms.is_some() { "revoked" } else { "active" },
        "created_at": timestamp(token.created_at_ms),
        "last_used_at": token.last_used_at_ms.and_then(timestamp),
        "revoked_at": token.revoked_at_ms.and_then(timestamp),
        "value_stored": token.value_stored,
    })
}

async fn overview(State(state): State<AdminState>) -> Response {
    let events = state.events.clone();
    let tokens = state.tokens.clone();
    let result = blocking(move || Ok((events.facets()?, tokens.list_tokens(None)?))).await;
    let (facets, tokens) = match result {
        Ok(found) => found,
        Err(e) => return store_error(e),
    };
    let active = |kind| {
        tokens
            .iter()
            .filter(|t| t.kind == kind && t.revoked_at_ms.is_none())
            .count()
    };
    let counts = |items: &[(String, u64)]| -> Vec<Value> {
        items
            .iter()
            .map(|(name, count)| json!({ "name": name, "count": count }))
            .collect()
    };
    Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "public_url": state.public_url.as_deref(),
        "insecure_reveal_tokens": state.reveal_tokens,
        "events": {
            "total": facets.total,
            "latest_seq": facets.latest_seq,
            "sources": counts(&facets.sources),
            "types": counts(&facets.events),
            "hosts": counts(&facets.hosts),
            "repos": counts(&facets.repos),
        },
        "tokens": {
            "sender": active(TokenKind::Sender),
            "consumer": active(TokenKind::Consumer),
        },
    }))
    .into_response()
}

/// Newest first, for browsing: `before` is the cursor.
async fn list_events(State(state): State<AdminState>, RawQuery(query): RawQuery) -> Response {
    let pairs = query_pairs(query.as_deref());
    let filter = event_filter(&pairs);
    let (before, limit) = match (
        number::<i64>(&pairs, "before"),
        number::<usize>(&pairs, "limit"),
    ) {
        (Ok(b), Ok(l)) => (b, l.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT)),
        (Err(e), _) | (_, Err(e)) => return error(StatusCode::BAD_REQUEST, &e),
    };
    let events = state.events.clone();
    match blocking(move || events.list_recent(&filter, before, limit)).await {
        Ok(found) => {
            // A full page may have more behind it.
            let next_before = (found.len() == limit)
                .then(|| found.last().map(|e| e.seq))
                .flatten();
            let found: Vec<Value> = found.iter().map(event_json).collect();
            Json(json!({ "events": found, "next_before": next_before })).into_response()
        }
        Err(e) => store_error(e),
    }
}

async fn get_event(State(state): State<AdminState>, Path(seq): Path<i64>) -> Response {
    event_response(state.events.clone(), seq).await
}

async fn get_raw(State(state): State<AdminState>, Path(seq): Path<i64>) -> Response {
    raw_response(state.events.clone(), seq).await
}

async fn list_channels(State(state): State<AdminState>) -> Response {
    channels_response(state.events.clone()).await
}

async fn reset_events(State(state): State<AdminState>, RawQuery(query): RawQuery) -> Response {
    let channel = query_pairs(query.as_deref())
        .into_iter()
        .find(|(k, _)| k == "channel")
        .map(|(_, v)| v);
    if channel.as_deref().is_some_and(|c| !valid_channel(c)) {
        return error(StatusCode::BAD_REQUEST, "invalid channel name");
    }
    let events = state.events.clone();
    match blocking(move || events.delete(channel.as_deref())).await {
        Ok(deleted) => Json(json!({ "deleted": deleted })).into_response(),
        Err(e) => store_error(e),
    }
}

async fn list_tokens(State(state): State<AdminState>, RawQuery(query): RawQuery) -> Response {
    let kind = match query_pairs(query.as_deref())
        .into_iter()
        .find(|(k, _)| k == "kind")
    {
        None => None,
        Some((_, v)) => match TokenKind::parse(&v) {
            Some(kind) => Some(kind),
            None => return error(StatusCode::BAD_REQUEST, "kind must be sender or consumer"),
        },
    };
    let tokens = state.tokens.clone();
    match blocking(move || tokens.list_tokens(kind)).await {
        Ok(found) => {
            let items: Vec<Value> = found.iter().map(token_json).collect();
            Json(json!({ "items": items })).into_response()
        }
        Err(e) => store_error(e),
    }
}

#[derive(Deserialize)]
struct CreateToken {
    kind: String,
    name: String,
    description: Option<String>,
}

/// The issued value is in this response only.
fn issued(status: StatusCode, token: &Token, value: &str) -> Response {
    (
        status,
        Json(json!({ "token": token_json(token), "value": value })),
    )
        .into_response()
}

async fn create_token(State(state): State<AdminState>, Json(body): Json<CreateToken>) -> Response {
    let Some(kind) = TokenKind::parse(&body.kind) else {
        return error(StatusCode::BAD_REQUEST, "kind must be sender or consumer");
    };
    let name = body.name.trim().to_string();
    if name.is_empty() || name.chars().count() > 80 {
        return error(StatusCode::BAD_REQUEST, "name must be 1 to 80 characters");
    }
    let description = body
        .description
        .map(|d| d.trim().to_string())
        .filter(|d| !d.is_empty());
    if description
        .as_ref()
        .is_some_and(|d| d.chars().count() > 500)
    {
        return error(
            StatusCode::BAD_REQUEST,
            "description must be at most 500 characters",
        );
    }
    let tokens = state.tokens.clone();
    let result = blocking(move || {
        let value = generate(kind)?;
        let token = tokens.create_token(
            &NewToken {
                kind,
                name,
                description,
                value: value.clone(),
                is_default: false,
            },
            now_ms(),
        )?;
        Ok((token, value))
    })
    .await;
    match result {
        Ok((token, value)) => {
            eprintln!("issued {} token {} ({})", token.kind, token.id, token.name);
            issued(StatusCode::CREATED, &token, &value)
        }
        Err(e) => store_error(e),
    }
}

async fn rotate_token(State(state): State<AdminState>, Path(id): Path<String>) -> Response {
    let tokens = state.tokens.clone();
    let result = blocking(move || {
        let Some(token) = tokens.get_token(&id)? else {
            return Ok(None);
        };
        let value = generate(token.kind)?;
        Ok(tokens.rotate_token(&id, &value)?.map(|t| (t, value)))
    })
    .await;
    match result {
        Ok(Some((token, value))) => {
            eprintln!("rotated {} token {} ({})", token.kind, token.id, token.name);
            issued(StatusCode::OK, &token, &value)
        }
        Ok(None) => error(StatusCode::NOT_FOUND, "no such active token"),
        Err(e) => store_error(e),
    }
}

async fn revoke_token(State(state): State<AdminState>, Path(id): Path<String>) -> Response {
    let tokens = state.tokens.clone();
    match blocking(move || tokens.revoke_token(&id, now_ms())).await {
        Ok(Some(token)) => {
            eprintln!("revoked {} token {} ({})", token.kind, token.id, token.name);
            Json(json!({ "token": token_json(&token) })).into_response()
        }
        Ok(None) => error(StatusCode::NOT_FOUND, "no such token"),
        Err(e) => store_error(e),
    }
}

/// A token's stored value, only in insecure reveal mode.
async fn token_value(State(state): State<AdminState>, Path(id): Path<String>) -> Response {
    if !state.reveal_tokens {
        return error(
            StatusCode::FORBIDDEN,
            "token values can be shown only in insecure reveal mode (HOOKSINK_INSECURE_REVEAL_TOKENS)",
        );
    }
    let tokens = state.tokens.clone();
    let lookup = id.clone();
    let result =
        blocking(move || Ok((tokens.get_token(&lookup)?, tokens.token_value(&lookup)?))).await;
    match result {
        Ok((Some(token), Some(value))) => {
            eprintln!(
                "revealed {} token {} ({})",
                token.kind, token.id, token.name
            );
            Json(json!({ "token": token_json(&token), "value": value })).into_response()
        }
        Ok((Some(_), None)) => error(
            StatusCode::NOT_FOUND,
            "this token's value is not stored: it is revoked, or it was issued before reveal mode was on; rotate it to get a new value",
        ),
        Ok((None, _)) => error(StatusCode::NOT_FOUND, "no such token"),
        Err(e) => store_error(e),
    }
}
