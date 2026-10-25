//! Signature checks and sender classification.

use axum::http::HeaderMap;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Signature headers whose value is `sha256=<hex>`.
const SIGNATURE_HEADERS: &[&str] = &["x-hub-signature-256", "x-hub-signature"];

/// The HMAC-SHA256 digests a request carries, decoded.
///
/// Accepted forms:
/// - `X-Hub-Signature-256: sha256=<hex>` (GitHub);
/// - `X-Hub-Signature: sha256=<hex>` (Jira).
///
/// GitHub's legacy SHA-1 form of `X-Hub-Signature` is not accepted. A
/// malformed value is returned as an empty digest, which matches nothing,
/// so a request that carries a signature never falls back to other
/// credentials.
pub fn signatures(headers: &HeaderMap) -> Vec<Vec<u8>> {
    SIGNATURE_HEADERS
        .iter()
        .filter_map(|name| header(headers, name))
        .filter_map(|value| value.strip_prefix("sha256="))
        .map(|digest| hex::decode(digest).unwrap_or_default())
        .collect()
}

/// Whether `digest` is the HMAC-SHA256 of `body` under `secret`.
pub fn hmac_matches(secret: &[u8], body: &[u8], digest: &[u8]) -> bool {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(body);
    mac.verify_slice(digest).is_ok()
}

/// Whether any signature on the request is `body` signed with `secret`.
pub fn signature_matches(secret: &[u8], headers: &HeaderMap, body: &[u8]) -> bool {
    signatures(headers)
        .iter()
        .any(|digest| hmac_matches(secret, body, digest))
}

/// `sha256=<hex>` of `body` under `secret`, as GitHub and Jira send it.
pub fn sign(secret: &[u8], body: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(body);
    format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
}

#[derive(Debug, PartialEq, Eq)]
pub struct Sender {
    pub source: &'static str,
    pub event: Option<String>,
    /// Stable across redeliveries of the same delivery, where the sender
    /// provides one.
    pub delivery_id: Option<String>,
}

pub fn classify(headers: &HeaderMap, body: &[u8]) -> Sender {
    let owned = |name| header(headers, name).map(str::to_string);
    if let Some(event) = owned("x-github-event") {
        return Sender {
            source: "github",
            event: Some(event),
            delivery_id: owned("x-github-delivery"),
        };
    }
    if let Some(event) = owned("x-gitlab-event") {
        return Sender {
            source: "gitlab",
            event: Some(event),
            delivery_id: owned("idempotency-key").or_else(|| owned("x-gitlab-event-uuid")),
        };
    }
    let jira_event = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("webhookEvent")?.as_str().map(str::to_string));
    if let Some(id) = owned("x-atlassian-webhook-identifier") {
        return Sender {
            source: "jira",
            event: jira_event,
            delivery_id: Some(id),
        };
    }
    if jira_event.is_some() {
        return Sender {
            source: "jira",
            event: jira_event,
            delivery_id: None,
        };
    }
    Sender {
        source: "generic",
        event: None,
        delivery_id: owned("idempotency-key"),
    }
}

pub fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(*name, value.parse().unwrap());
        }
        map
    }

    #[test]
    fn github_and_jira_hmac() {
        let body = b"{\"a\":1}";
        let sig = sign(b"s3cret", body);
        assert!(signature_matches(
            b"s3cret",
            &headers(&[("x-hub-signature-256", &sig)]),
            body
        ));
        assert!(signature_matches(
            b"s3cret",
            &headers(&[("x-hub-signature", &sig)]),
            body
        ));
        assert!(!signature_matches(
            b"other",
            &headers(&[("x-hub-signature-256", &sig)]),
            body
        ));
        assert!(!signature_matches(
            b"s3cret",
            &headers(&[("x-hub-signature-256", &sig)]),
            b"{\"a\":2}"
        ));
    }

    #[test]
    fn rejects_sha1_malformed_and_missing() {
        let body = b"x";
        assert!(signatures(&headers(&[("x-hub-signature", "sha1=0000")])).is_empty());
        let malformed = headers(&[("x-hub-signature-256", "sha256=zz")]);
        assert_eq!(signatures(&malformed), vec![Vec::<u8>::new()]);
        assert!(!signature_matches(b"k", &malformed, body));
        assert!(!signature_matches(b"k", &HeaderMap::new(), body));
    }

    #[test]
    fn classifies_senders() {
        let gh = classify(
            &headers(&[("x-github-event", "issues"), ("x-github-delivery", "d1")]),
            b"{}",
        );
        assert_eq!(gh.source, "github");
        assert_eq!(gh.event.as_deref(), Some("issues"));
        assert_eq!(gh.delivery_id.as_deref(), Some("d1"));

        let gl = classify(
            &headers(&[
                ("x-gitlab-event", "Push Hook"),
                ("x-gitlab-event-uuid", "u"),
                ("idempotency-key", "k"),
            ]),
            b"{}",
        );
        assert_eq!(
            (gl.source, gl.delivery_id.as_deref()),
            ("gitlab", Some("k"))
        );

        let jira = classify(
            &headers(&[("x-atlassian-webhook-identifier", "j1")]),
            br#"{"webhookEvent":"jira:issue_created"}"#,
        );
        assert_eq!(jira.source, "jira");
        assert_eq!(jira.event.as_deref(), Some("jira:issue_created"));
        assert_eq!(jira.delivery_id.as_deref(), Some("j1"));

        assert_eq!(
            classify(&HeaderMap::new(), br#"{"webhookEvent":"x"}"#).source,
            "jira"
        );
        assert_eq!(classify(&HeaderMap::new(), b"not json").source, "generic");
    }
}
