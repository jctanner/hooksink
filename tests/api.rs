//! HTTP behavior through the real routers and an in-memory store.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tokio::sync::watch;
use tower::ServiceExt;

use webhook_sink_service::admin::{self, AdminState};
use webhook_sink_service::api::{self, AppState, Settings};
use webhook_sink_service::store::SqliteStore;
use webhook_sink_service::tokens::{TokenKind, TokenStore};
use webhook_sink_service::verify::{sign, signature_matches};

const SENDER: &str = "whs_test-sender-token-value-0001";
const CONSUMER: &str = "whc_test-consumer-token-value-01";
const ADMIN: &str = "admin-test-key";

struct Sink {
    app: Router,
    admin: Router,
    store: Arc<SqliteStore>,
    shutdown: watch::Sender<bool>,
}

fn sink_with(configure: impl FnOnce(&mut Settings)) -> Sink {
    sink_with_mode(configure, false)
}

/// A sink with insecure reveal mode set as given.
fn sink_with_mode(configure: impl FnOnce(&mut Settings), reveal: bool) -> Sink {
    let mut settings = Settings {
        max_body_bytes: 1024 * 1024,
        max_wait: Duration::from_secs(10),
    };
    configure(&mut settings);
    let (shutdown, shutdown_rx) = watch::channel(false);
    let store = Arc::new(
        SqliteStore::open_in_memory()
            .unwrap()
            .keep_consumer_values(reveal),
    );
    store
        .ensure_default(TokenKind::Sender, SENDER, "default-sender", 1)
        .unwrap();
    store
        .ensure_default(TokenKind::Consumer, CONSUMER, "default-consumer", 1)
        .unwrap();
    Sink {
        app: api::router(AppState::new(
            store.clone(),
            store.clone(),
            settings,
            shutdown_rx,
        )),
        admin: admin::router(AdminState::new(
            store.clone(),
            store.clone(),
            ADMIN.into(),
            Some("http://sink.test/".into()),
            reveal,
        )),
        store,
        shutdown,
    }
}

fn sink() -> Sink {
    sink_with(|_| {})
}

async fn call(app: &Router, request: Request<Body>) -> (StatusCode, Vec<u8>) {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, body.to_vec())
}

fn parse(body: &[u8]) -> Value {
    serde_json::from_slice(body).unwrap_or(Value::Null)
}

impl Sink {
    /// Post with explicit headers and no other credentials.
    async fn post_raw(
        &self,
        uri: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> (StatusCode, Value) {
        let mut request = Request::post(uri);
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let (status, body) =
            call(&self.app, request.body(Body::from(body.to_vec())).unwrap()).await;
        (status, parse(&body))
    }

    /// Post signed with the default sender token, as GitHub would.
    async fn post(
        &self,
        channel: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> (StatusCode, Value) {
        let signature = sign(SENDER.as_bytes(), body);
        let mut all = headers.to_vec();
        all.push(("x-hub-signature-256", &signature));
        self.post_raw(&format!("/hooks/{channel}"), &all, body)
            .await
    }

    async fn get_as(&self, uri: &str, token: Option<&str>) -> (StatusCode, Vec<u8>) {
        let mut request = Request::get(uri);
        if let Some(token) = token {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        call(&self.app, request.body(Body::empty()).unwrap()).await
    }

    /// Read as the default consumer.
    async fn get(&self, uri: &str) -> (StatusCode, Value) {
        let (status, body) = self.get_as(uri, Some(CONSUMER)).await;
        (status, parse(&body))
    }

    async fn admin(&self, method: &str, uri: &str, body: Option<Value>) -> (StatusCode, Value) {
        let mut request = Request::builder()
            .method(method)
            .uri(format!("/api/private/v1{uri}"))
            .header("authorization", format!("Bearer {ADMIN}"));
        let body = match body {
            Some(value) => {
                request = request.header("content-type", "application/json");
                Body::from(value.to_string())
            }
            None => Body::empty(),
        };
        let (status, body) = call(&self.admin, request.body(body).unwrap()).await;
        (status, parse(&body))
    }
}

fn seqs(page: &Value) -> Vec<i64> {
    page["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["seq"].as_i64().unwrap())
        .collect()
}

/// URI, headers, body, and the expected authentication method.
type Case<'a> = (String, Vec<(&'a str, &'a str)>, &'a [u8], &'a str);

const ISSUE: &[u8] = br#"{"action":"opened","issue":{"number":1}}"#;

#[tokio::test]
async fn signed_github_delivery_identifies_its_sender_token() {
    let sink = sink();
    let (status, ack) = sink
        .post(
            "github",
            &[
                ("content-type", "application/json"),
                ("x-github-event", "issues"),
                ("x-github-delivery", "d-1"),
            ],
            ISSUE,
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(ack["duplicate"], false);

    let (status, page) = sink.get("/events?after=0").await;
    assert_eq!(status, StatusCode::OK);
    let event = &page["events"][0];
    assert_eq!(event["seq"], ack["seq"]);
    assert_eq!(event["channel"], "github");
    assert_eq!(event["source"], "github");
    assert_eq!(event["event"], "issues");
    assert_eq!(event["delivery_id"], "d-1");
    assert_eq!(event["sender"]["name"], "default-sender");
    assert_eq!(event["sender"]["method"], "hmac");
    assert_eq!(event["payload"]["action"], "opened");
    assert_eq!(page["next_after"], ack["seq"]);
}

#[tokio::test]
async fn deliveries_without_a_valid_sender_token_are_rejected() {
    let sink = sink();
    let wrong = sign(b"not-a-sender-token", ISSUE);
    for headers in [
        vec![("x-github-event", "issues")],
        vec![("x-hub-signature-256", wrong.as_str())],
        vec![("authorization", "Bearer whs_unknown")],
        vec![("x-gitlab-token", "whs_unknown")],
        // A consumer token is not a sender token.
        vec![("authorization", "Bearer whc_test-consumer-token-value-01")],
    ] {
        let (status, _) = sink.post_raw("/hooks/github", &headers, ISSUE).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{headers:?}");
    }
    // A signature that does not match is decisive, even with a valid
    // bearer token beside it: the body may have been altered.
    let (status, _) = sink
        .post_raw(
            "/hooks/github",
            &[
                ("x-hub-signature-256", &wrong),
                ("authorization", &format!("Bearer {SENDER}")),
            ],
            ISSUE,
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(seqs(&sink.get("/events").await.1).is_empty());
}

#[tokio::test]
async fn every_sender_credential_form_is_accepted() {
    let sink = sink();
    let jira = br#"{"webhookEvent":"jira:issue_created"}"#;
    let jira_signature = sign(SENDER.as_bytes(), jira);
    let bearer = format!("Bearer {SENDER}");
    let cases: Vec<Case> = vec![
        (
            "/hooks/jira".into(),
            vec![
                ("x-atlassian-webhook-identifier", "j-1"),
                ("x-hub-signature", &jira_signature),
            ],
            jira,
            "hmac",
        ),
        (
            "/hooks/gitlab".into(),
            vec![("x-gitlab-event", "Push Hook"), ("x-gitlab-token", SENDER)],
            b"{}",
            "gitlab-token",
        ),
        (
            "/hooks/script".into(),
            vec![("authorization", &bearer)],
            b"{}",
            "bearer",
        ),
        (
            format!("/hooks/script?token={SENDER}"),
            vec![],
            b"{}",
            "query",
        ),
    ];
    for (uri, headers, body, _) in &cases {
        let (status, _) = sink.post_raw(uri, headers, body).await;
        assert_eq!(status, StatusCode::ACCEPTED, "{uri}");
    }
    let (_, page) = sink.get("/events").await;
    let events = page["events"].as_array().unwrap();
    for (event, (_, _, _, method)) in events.iter().zip(&cases) {
        assert_eq!(event["sender"]["method"], *method);
    }
    assert_eq!(events[0]["source"], "jira");
    assert_eq!(events[0]["event"], "jira:issue_created");
    assert_eq!(events[1]["source"], "gitlab");
    // Credentials are never stored.
    assert_eq!(events[1]["headers"]["x-gitlab-token"], "[redacted]");
    assert_eq!(events[2]["headers"]["authorization"], "[redacted]");
}

#[tokio::test]
async fn consumers_need_an_active_consumer_token() {
    let sink = sink();
    sink.post("open", &[], b"{}").await;
    for uri in ["/events", "/events/1", "/events/1/raw", "/channels"] {
        assert_eq!(
            sink.get_as(uri, None).await.0,
            StatusCode::UNAUTHORIZED,
            "{uri}"
        );
        assert_eq!(
            sink.get_as(uri, Some(SENDER)).await.0,
            StatusCode::UNAUTHORIZED,
            "{uri}"
        );
        assert_eq!(
            sink.get_as(uri, Some(CONSUMER)).await.0,
            StatusCode::OK,
            "{uri}"
        );
    }
    assert_eq!(sink.get_as("/healthz", None).await.0, StatusCode::OK);
    assert_eq!(sink.get_as("/", None).await.0, StatusCode::OK);
    // Consumers cannot delete; resets are an admin action.
    let delete = Request::delete("/events")
        .header("authorization", format!("Bearer {CONSUMER}"))
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        call(&sink.app, delete).await.0,
        StatusCode::METHOD_NOT_ALLOWED
    );
}

#[tokio::test]
async fn duplicate_delivery_is_acknowledged_but_not_stored_twice() {
    let sink = sink();
    let headers = [("x-github-event", "push"), ("x-github-delivery", "same")];
    let (first_status, first) = sink.post("github", &headers, b"{}").await;
    let (second_status, second) = sink.post("github", &headers, b"{}").await;
    assert_eq!(first_status, StatusCode::ACCEPTED);
    assert_eq!(second_status, StatusCode::OK);
    assert_eq!(second["duplicate"], true);
    assert_eq!(second["seq"], first["seq"]);
    assert_eq!(seqs(&sink.get("/events").await.1).len(), 1);
}

#[tokio::test]
async fn cursor_paging() {
    let sink = sink();
    for n in 0..5 {
        sink.post("pages", &[], format!("{{\"n\":{n}}}").as_bytes())
            .await;
    }
    let (_, first) = sink.get("/events?limit=2").await;
    assert_eq!(seqs(&first), vec![1, 2]);
    let (_, second) = sink
        .get(&format!("/events?limit=2&after={}", first["next_after"]))
        .await;
    assert_eq!(seqs(&second), vec![3, 4]);
    let (_, third) = sink
        .get(&format!("/events?limit=2&after={}", second["next_after"]))
        .await;
    assert_eq!(seqs(&third), vec![5]);
    let (_, done) = sink
        .get(&format!("/events?after={}", third["next_after"]))
        .await;
    assert!(seqs(&done).is_empty());
    assert_eq!(done["next_after"], 5);
    assert_eq!(sink.get("/events?after=x").await.0, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn query_time_filters() {
    let sink = sink();
    for (channel, kind) in [
        ("gh", "issues"),
        ("gh", "pull_request"),
        ("gh2", "issues"),
        ("gh", "push"),
    ] {
        sink.post(channel, &[("x-github-event", kind)], b"{}").await;
    }
    let jira = br#"{"webhookEvent":"jira:issue_created"}"#;
    sink.post("jira", &[], jira).await;

    let cases = [
        ("/events?source=github", vec![1, 2, 3, 4]),
        ("/events?source=jira", vec![5]),
        ("/events?event=issues", vec![1, 3]),
        ("/events?event=issues,push", vec![1, 3, 4]),
        ("/events?event=issues&event=pull_request", vec![1, 2, 3]),
        ("/events?channel=gh&event=issues", vec![1]),
        ("/events?source=github&channel=jira", vec![]),
    ];
    for (uri, expected) in cases {
        assert_eq!(seqs(&sink.get(uri).await.1), expected, "{uri}");
    }
    let sender = &sink.get("/events/1").await.1["sender"]["token_id"];
    let (_, by_sender) = sink
        .get(&format!("/events?sender={}", sender.as_str().unwrap()))
        .await;
    assert_eq!(seqs(&by_sender).len(), 5);
    assert!(seqs(&sink.get("/events?sender=tok_other").await.1).is_empty());
}

#[tokio::test]
async fn long_poll_wakes_on_a_matching_event() {
    let sink = sink();
    let app = sink.app.clone();
    let started = Instant::now();
    let waiter = tokio::spawn(async move {
        let request = Request::get("/events?source=jira&wait=5")
            .header("authorization", format!("Bearer {CONSUMER}"))
            .body(Body::empty())
            .unwrap();
        parse(&call(&app, request).await.1)
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    // An event that does not match does not end the wait.
    sink.post("gh", &[("x-github-event", "push")], b"{}").await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!waiter.is_finished());
    sink.post("jira", &[], br#"{"webhookEvent":"jira:issue_updated"}"#)
        .await;

    let page = tokio::time::timeout(Duration::from_secs(2), waiter)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(page["events"][0]["event"], "jira:issue_updated");
    assert!(started.elapsed() < Duration::from_secs(3));
}

#[tokio::test]
async fn long_poll_times_out_empty_and_is_capped() {
    let sink = sink_with(|s| s.max_wait = Duration::from_secs(1));
    let started = Instant::now();
    let (status, page) = sink.get("/events?wait=30").await;
    let elapsed = started.elapsed();
    assert_eq!(status, StatusCode::OK);
    assert!(seqs(&page).is_empty());
    assert!(elapsed >= Duration::from_millis(900), "{elapsed:?}");
    assert!(elapsed < Duration::from_secs(3), "{elapsed:?}");
}

#[tokio::test]
async fn shutdown_releases_long_polls() {
    let sink = sink();
    let app = sink.app.clone();
    let waiter = tokio::spawn(async move {
        let request = Request::get("/events?wait=10")
            .header("authorization", format!("Bearer {CONSUMER}"))
            .body(Body::empty())
            .unwrap();
        call(&app, request).await.0
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    sink.shutdown.send_replace(true);
    let status = tokio::time::timeout(Duration::from_secs(2), waiter)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn body_over_the_cap_is_rejected() {
    let sink = sink_with(|s| s.max_body_bytes = 1024);
    let (status, _) = sink.post("big", &[], &vec![b'a'; 2048]).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    let (status, _) = sink.post("big", &[], &vec![b'a'; 1000]).await;
    assert_eq!(status, StatusCode::ACCEPTED);
}

#[tokio::test]
async fn raw_body_is_byte_exact_and_its_signature_reverifies() {
    let sink = sink();
    // Whitespace and key order that a JSON round trip would not keep.
    let body = b"{ \"z\": 1,\n  \"a\": [1.50, \"\\u00e9\"] }";
    let (_, ack) = sink
        .post(
            "signed",
            &[
                ("content-type", "application/json"),
                ("x-github-event", "push"),
            ],
            body,
        )
        .await;
    let seq = ack["seq"].as_i64().unwrap();

    let (status, raw) = sink
        .get_as(&format!("/events/{seq}/raw"), Some(CONSUMER))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(raw, body);

    let (_, event) = sink.get(&format!("/events/{seq}")).await;
    let stored = event["headers"]["x-hub-signature-256"].as_str().unwrap();
    let mut headers = axum::http::HeaderMap::new();
    headers.insert("x-hub-signature-256", stored.parse().unwrap());
    assert!(signature_matches(SENDER.as_bytes(), &headers, &raw));
}

#[tokio::test]
async fn non_json_bodies() {
    let sink = sink();
    let (_, text) = sink
        .post("misc", &[("content-type", "text/plain")], b"hello")
        .await;
    let (_, binary) = sink.post("misc", &[], &[0xff, 0x00, 0xfe]).await;
    let (_, t) = sink.get(&format!("/events/{}", text["seq"])).await;
    let (_, b) = sink.get(&format!("/events/{}", binary["seq"])).await;
    assert_eq!(t["body"], "hello");
    assert_eq!(t["source"], "generic");
    assert_eq!(b["body_base64"], "/wD+");
    assert_eq!(b["size"], 3);
    let (status, _) = sink.get("/events/999").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn invalid_channel_names_are_rejected() {
    let sink = sink();
    for channel in ["..", ".hidden", "a$b"] {
        let (status, _) = sink.post(channel, &[], b"{}").await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{channel}");
    }
}

#[tokio::test]
async fn admin_api_requires_the_admin_key() {
    let sink = sink();
    for key in [None, Some(CONSUMER), Some("wrong")] {
        let mut request = Request::get("/api/private/v1/overview");
        if let Some(key) = key {
            request = request.header("authorization", format!("Bearer {key}"));
        }
        let (status, _) = call(&sink.admin, request.body(Body::empty()).unwrap()).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{key:?}");
    }
    // The console shell is public; its data is not.
    let (status, page) = call(
        &sink.admin,
        Request::get("/admin/").body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(String::from_utf8(page).unwrap().contains("webhook-sink"));
    let (status, overview) = sink.admin("GET", "/overview", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(overview["public_url"], "http://sink.test");
    assert_eq!(overview["tokens"]["sender"], 1);
    assert_eq!(overview["tokens"]["consumer"], 1);
}

#[tokio::test]
async fn issued_tokens_work_until_rotated_or_revoked() {
    let sink = sink();
    let (status, issued) = sink
        .admin(
            "POST",
            "/tokens",
            Some(
                json!({ "kind": "sender", "name": "github-emulator", "description": "repo hooks" }),
            ),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let value = issued["value"].as_str().unwrap().to_string();
    let id = issued["token"]["id"].as_str().unwrap().to_string();
    assert!(value.starts_with("whs_"));
    assert_eq!(issued["token"]["prefix"], value[..12]);

    let post = |secret: String| {
        let sink = &sink;
        async move {
            let signature = sign(secret.as_bytes(), b"{}");
            sink.post_raw("/hooks/gh", &[("x-hub-signature-256", &signature)], b"{}")
                .await
                .0
        }
    };
    assert_eq!(post(value.clone()).await, StatusCode::ACCEPTED);
    let (_, page) = sink.get("/events").await;
    assert_eq!(page["events"][0]["sender"]["name"], "github-emulator");

    // The listing never includes a value.
    let (_, list) = sink.admin("GET", "/tokens?kind=sender", None).await;
    assert_eq!(list["items"].as_array().unwrap().len(), 2);
    assert!(!list.to_string().contains(&value));
    assert!(list["items"][1]["last_used_at"].is_string());

    let (status, rotated) = sink
        .admin("POST", &format!("/tokens/{id}/rotate"), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    let new_value = rotated["value"].as_str().unwrap().to_string();
    assert_ne!(new_value, value);
    assert_eq!(post(value).await, StatusCode::UNAUTHORIZED);
    assert_eq!(post(new_value.clone()).await, StatusCode::ACCEPTED);

    let (status, revoked) = sink
        .admin("POST", &format!("/tokens/{id}/revoke"), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(revoked["token"]["status"], "revoked");
    assert_eq!(post(new_value).await, StatusCode::UNAUTHORIZED);
    let (status, _) = sink
        .admin("POST", &format!("/tokens/{id}/rotate"), None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn issued_consumer_tokens_read_and_can_be_revoked() {
    let sink = sink();
    sink.post("gh", &[], b"{}").await;
    let (_, issued) = sink
        .admin(
            "POST",
            "/tokens",
            Some(json!({ "kind": "consumer", "name": "markovd" })),
        )
        .await;
    let value = issued["value"].as_str().unwrap();
    assert!(value.starts_with("whc_"));
    assert_eq!(sink.get_as("/events", Some(value)).await.0, StatusCode::OK);
    let id = issued["token"]["id"].as_str().unwrap();
    sink.admin("POST", &format!("/tokens/{id}/revoke"), None)
        .await;
    assert_eq!(
        sink.get_as("/events", Some(value)).await.0,
        StatusCode::UNAUTHORIZED
    );
    // Other consumers are unaffected.
    assert_eq!(sink.get("/events").await.0, StatusCode::OK);
}

#[tokio::test]
async fn token_requests_are_validated() {
    let sink = sink();
    for body in [
        json!({ "kind": "admin", "name": "x" }),
        json!({ "kind": "sender", "name": "  " }),
        json!({ "kind": "sender", "name": "x".repeat(81) }),
    ] {
        let (status, _) = sink.admin("POST", "/tokens", Some(body.clone())).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    }
    let (status, _) = sink.admin("GET", "/tokens?kind=other", None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = sink.admin("POST", "/tokens/tok_missing/revoke", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn admin_browses_newest_first_and_resets() {
    let sink = sink();
    for n in 0..5 {
        let channel = if n % 2 == 0 { "a" } else { "b" };
        sink.post(channel, &[("x-github-event", "push")], b"{}")
            .await;
    }
    let (_, page) = sink.admin("GET", "/events?limit=2", None).await;
    assert_eq!(seqs(&page), vec![5, 4]);
    assert_eq!(page["next_before"], 4);
    let (_, older) = sink.admin("GET", "/events?limit=2&before=4", None).await;
    assert_eq!(seqs(&older), vec![3, 2]);
    let (_, last) = sink.admin("GET", "/events?limit=2&before=2", None).await;
    assert_eq!(seqs(&last), vec![1]);
    assert_eq!(last["next_before"], Value::Null);
    let (_, only_a) = sink.admin("GET", "/events?channel=a", None).await;
    assert_eq!(seqs(&only_a), vec![5, 3, 1]);

    let (_, overview) = sink.admin("GET", "/overview", None).await;
    assert_eq!(overview["events"]["total"], 5);
    assert_eq!(overview["events"]["types"][0]["name"], "push");

    let (status, deleted) = sink.admin("DELETE", "/events?channel=a", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(deleted["deleted"], 3);
    let (_, deleted) = sink.admin("DELETE", "/events", None).await;
    assert_eq!(deleted["deleted"], 2);
    let (status, _) = sink.admin("DELETE", "/events?channel=..", None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Cursors stay valid: the next event's seq is past every earlier one.
    let (_, ack) = sink.post("a", &[], b"{}").await;
    assert_eq!(ack["seq"], 6);
    assert!(sink.store.list_tokens(None).unwrap().len() == 2);
}

#[tokio::test]
async fn token_values_are_hidden_outside_reveal_mode() {
    let sink = sink();
    let (_, list) = sink.admin("GET", "/tokens", None).await;
    let consumer = list["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["kind"] == "consumer")
        .unwrap();
    assert_eq!(consumer["value_stored"], false);
    let (status, body) = sink
        .admin(
            "GET",
            &format!("/tokens/{}/value", consumer["id"].as_str().unwrap()),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .contains("WEBHOOK_SINK_INSECURE_REVEAL_TOKENS")
    );
    let (_, overview) = sink.admin("GET", "/overview", None).await;
    assert_eq!(overview["insecure_reveal_tokens"], false);
}

#[tokio::test]
async fn reveal_mode_shows_every_active_token_value() {
    let sink = sink_with_mode(|_| {}, true);
    let (_, overview) = sink.admin("GET", "/overview", None).await;
    assert_eq!(overview["insecure_reveal_tokens"], true);

    let (_, list) = sink.admin("GET", "/tokens", None).await;
    let mut seen = Vec::new();
    for token in list["items"].as_array().unwrap() {
        assert_eq!(token["value_stored"], true);
        let (status, body) = sink
            .admin(
                "GET",
                &format!("/tokens/{}/value", token["id"].as_str().unwrap()),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        seen.push(body["value"].as_str().unwrap().to_string());
    }
    seen.sort();
    assert_eq!(seen, vec![CONSUMER.to_string(), SENDER.to_string()]);

    // An issued consumer token can be shown again, and still reads.
    let (_, issued) = sink
        .admin(
            "POST",
            "/tokens",
            Some(json!({ "kind": "consumer", "name": "dashboard" })),
        )
        .await;
    let id = issued["token"]["id"].as_str().unwrap();
    let (_, revealed) = sink
        .admin("GET", &format!("/tokens/{id}/value"), None)
        .await;
    assert_eq!(revealed["value"], issued["value"]);
    let value = revealed["value"].as_str().unwrap();
    assert_eq!(sink.get_as("/events", Some(value)).await.0, StatusCode::OK);

    // Not once revoked, and not for unknown IDs.
    sink.admin("POST", &format!("/tokens/{id}/revoke"), None)
        .await;
    let (status, _) = sink
        .admin("GET", &format!("/tokens/{id}/value"), None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = sink.admin("GET", "/tokens/tok_missing/value", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    // The value is never part of the listing, even in reveal mode.
    let (_, list) = sink.admin("GET", "/tokens", None).await;
    assert!(!list.to_string().contains(CONSUMER));
}

fn github_payload(host: &str, repo: &str) -> Vec<u8> {
    json!({
        "action": "opened",
        "repository": { "full_name": repo, "html_url": format!("https://{host}/{repo}") },
    })
    .to_string()
    .into_bytes()
}

#[tokio::test]
async fn consumers_filter_by_host_and_repo() {
    let sink = sink();
    for (host, repo) in [
        ("github.local", "fullsend-dev/triage-target"),
        ("github.local", "fullsend-dev/other"),
        ("github.com", "fullsend-dev/triage-target"),
        ("github.local", "markov/workflows"),
    ] {
        sink.post(
            "gh",
            &[("x-github-event", "issues")],
            &github_payload(host, repo),
        )
        .await;
    }
    let jira = br#"{"webhookEvent":"jira:issue_created","issue":{"key":"RHAIRFE-7","self":"https://jira.local/rest/api/2/issue/7"}}"#;
    sink.post("jira", &[], jira).await;

    let (_, first) = sink.get("/events/1").await;
    assert_eq!(first["host"], "github.local");
    assert_eq!(first["repo"], "fullsend-dev/triage-target");
    let (_, jira_event) = sink.get("/events/5").await;
    assert_eq!(
        (jira_event["host"].as_str(), jira_event["repo"].as_str()),
        (Some("jira.local"), Some("RHAIRFE"))
    );

    let cases = [
        ("/events?host=github.local", vec![1, 2, 4]),
        ("/events?host=github.com", vec![3]),
        ("/events?repo=fullsend-dev/triage-target", vec![1, 3]),
        (
            "/events?host=github.local&repo=fullsend-dev/triage-target",
            vec![1],
        ),
        ("/events?repo=fullsend-dev/*", vec![1, 2, 3]),
        (
            "/events?host=github.local&repo=fullsend-dev/*,markov/*",
            vec![1, 2, 4],
        ),
        ("/events?host=jira.local&repo=RHAIRFE", vec![5]),
        ("/events?repo=nobody/*", vec![]),
    ];
    for (uri, expected) in cases {
        assert_eq!(seqs(&sink.get(uri).await.1), expected, "{uri}");
    }

    // A long-poll filtered by repo wakes only for that repo.
    let app = sink.app.clone();
    let waiter = tokio::spawn(async move {
        let request = Request::get("/events?host=github.local&repo=markov/*&after=5&wait=5")
            .header("authorization", format!("Bearer {CONSUMER}"))
            .body(Body::empty())
            .unwrap();
        parse(&call(&app, request).await.1)
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    sink.post(
        "gh",
        &[("x-github-event", "push")],
        &github_payload("github.local", "fullsend-dev/other"),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!waiter.is_finished());
    sink.post(
        "gh",
        &[("x-github-event", "push")],
        &github_payload("github.local", "markov/engine"),
    )
    .await;
    let page = tokio::time::timeout(Duration::from_secs(2), waiter)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(page["events"][0]["repo"], "markov/engine");

    let (_, overview) = sink.admin("GET", "/overview", None).await;
    assert_eq!(overview["events"]["hosts"][0]["name"], "github.local");
    let repos: Vec<(String, u64)> = overview["events"]["repos"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (
                r["name"].as_str().unwrap().to_string(),
                r["count"].as_u64().unwrap(),
            )
        })
        .collect();
    assert!(
        repos.contains(&("fullsend-dev/triage-target".into(), 2)),
        "{repos:?}"
    );
    assert!(repos.contains(&("RHAIRFE".into(), 1)), "{repos:?}");
    let (_, admin_page) = sink
        .admin("GET", "/events?repo=fullsend-dev/*&host=github.local", None)
        .await;
    // Newest first; seq 6 is the fullsend-dev/other push from the long-poll step.
    assert_eq!(seqs(&admin_page), vec![6, 2, 1]);
}
