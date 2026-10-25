//! Sender and consumer tokens.
//!
//! A sender token's value is also its webhook signing secret: paste it as
//! the hook's `secret` in GitHub or Jira, and the sink identifies the token
//! by the HMAC signature. Signature checks need the raw value, so sender
//! values are stored. Consumer values are stored only as a SHA-256
//! fingerprint, unless insecure reveal mode keeps them too. Either kind of
//! value is shown once, when it is issued or rotated, except in insecure
//! reveal mode, where the admin console can show stored values again.

use std::fmt;

use sha2::{Digest, Sha256};

use crate::store::{StoreError, StoreResult};

const VALUE_LENGTH: usize = 40;
const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
/// Characters of a value kept for display, prefix included.
const DISPLAY_PREFIX: usize = 12;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenKind {
    Sender,
    Consumer,
}

impl TokenKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sender => "sender",
            Self::Consumer => "consumer",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "sender" => Some(Self::Sender),
            "consumer" => Some(Self::Consumer),
            _ => None,
        }
    }

    /// Prefix of generated values, so a leaked value says what it is.
    pub fn value_prefix(self) -> &'static str {
        match self {
            Self::Sender => "whs_",
            Self::Consumer => "whc_",
        }
    }
}

impl fmt::Display for TokenKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A token as listed: never its value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Token {
    pub id: String,
    pub kind: TokenKind,
    pub name: String,
    pub description: Option<String>,
    /// The start of the value, for recognising it.
    pub prefix: String,
    pub is_default: bool,
    pub created_at_ms: i64,
    pub last_used_at_ms: Option<i64>,
    pub revoked_at_ms: Option<i64>,
    /// Whether the store holds the value, so it can be revealed.
    pub value_stored: bool,
}

#[derive(Clone, Debug)]
pub struct NewToken {
    pub kind: TokenKind,
    pub name: String,
    pub description: Option<String>,
    pub value: String,
    pub is_default: bool,
}

/// An active sender token's ID and signing secret.
#[derive(Clone)]
pub struct SenderKey {
    pub id: String,
    pub value: String,
}

/// What [`TokenStore::ensure_default`] found or did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DefaultToken {
    Created(Token),
    Existing(Token),
    /// The configured value belongs to a revoked token, which stays
    /// revoked: an admin's revocation outlives a restart.
    Revoked(Token),
}

pub trait TokenStore: Send + Sync {
    fn create_token(&self, token: &NewToken, now_ms: i64) -> StoreResult<Token>;
    fn list_tokens(&self, kind: Option<TokenKind>) -> StoreResult<Vec<Token>>;
    fn get_token(&self, id: &str) -> StoreResult<Option<Token>>;
    /// Replace an active token's value; `None` if missing or revoked.
    fn rotate_token(&self, id: &str, value: &str) -> StoreResult<Option<Token>>;
    /// `None` if there is no such token.
    fn revoke_token(&self, id: &str, now_ms: i64) -> StoreResult<Option<Token>>;
    fn sender_keys(&self) -> StoreResult<Vec<SenderKey>>;
    /// The active token of `kind` with this value.
    fn find_active(&self, kind: TokenKind, value: &str) -> StoreResult<Option<Token>>;
    /// Record use; written at most once a minute per token.
    fn touch_token(&self, id: &str, now_ms: i64) -> StoreResult<()>;
    /// Make the token with this value the default of its kind, creating it
    /// if it does not exist.
    fn ensure_default(
        &self,
        kind: TokenKind,
        value: &str,
        name: &str,
        now_ms: i64,
    ) -> StoreResult<DefaultToken>;
    /// An active token's stored value, for insecure reveal mode.
    fn token_value(&self, id: &str) -> StoreResult<Option<String>>;
    /// Drop stored consumer values, leaving only fingerprints; returns the
    /// count.
    fn forget_consumer_values(&self) -> StoreResult<u64>;
}

pub fn fingerprint(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

pub fn display_prefix(value: &str) -> String {
    value.chars().take(DISPLAY_PREFIX).collect()
}

/// A new random value for `kind`, such as `whs_` and 40 letters and digits.
pub fn generate(kind: TokenKind) -> StoreResult<String> {
    let mut value = String::from(kind.value_prefix());
    value.push_str(&random_chars(VALUE_LENGTH)?);
    Ok(value)
}

pub fn new_id() -> StoreResult<String> {
    let mut bytes = [0u8; 8];
    fill(&mut bytes)?;
    Ok(format!("tok_{}", hex::encode(bytes)))
}

fn random_chars(count: usize) -> StoreResult<String> {
    let mut out = String::with_capacity(count);
    let mut buffer = [0u8; 64];
    while out.len() < count {
        fill(&mut buffer)?;
        // Reject bytes past the largest multiple of 62, so each character
        // is uniform.
        for &byte in &buffer {
            if out.len() == count {
                break;
            }
            if byte < 248 {
                out.push(ALPHABET[(byte % 62) as usize] as char);
            }
        }
    }
    Ok(out)
}

fn fill(bytes: &mut [u8]) -> StoreResult<()> {
    getrandom::fill(bytes).map_err(|e| StoreError::new(format!("random source: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_values_are_prefixed_and_distinct() {
        let a = generate(TokenKind::Sender).unwrap();
        let b = generate(TokenKind::Sender).unwrap();
        assert!(a.starts_with("whs_"));
        assert_eq!(a.len(), 4 + VALUE_LENGTH);
        assert!(a[4..].bytes().all(|c| c.is_ascii_alphanumeric()));
        assert_ne!(a, b);
        assert!(generate(TokenKind::Consumer).unwrap().starts_with("whc_"));
        assert_eq!(display_prefix(&a), a[..12]);
    }

    #[test]
    fn ids_and_fingerprints() {
        let id = new_id().unwrap();
        assert!(id.starts_with("tok_") && id.len() == 20);
        assert_eq!(fingerprint("x"), fingerprint("x"));
        assert_ne!(fingerprint("x"), fingerprint("y"));
        assert_eq!(fingerprint("x").len(), 64);
    }
}
