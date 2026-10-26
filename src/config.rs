//! Runtime configuration, read from `HOOKSINK_*` environment variables.
//!
//! Each secret can be given directly, or as a path in a `*_FILE` variable,
//! as a mounted Kubernetes Secret lays it out.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

/// GitHub caps webhook payloads at 25 MB; accept the same.
pub const DEFAULT_MAX_BODY_BYTES: usize = 25 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct Config {
    pub listen: SocketAddr,
    pub admin_listen: SocketAddr,
    pub db_path: PathBuf,
    /// Without one, the admin listener does not start.
    pub admin_key: Option<String>,
    /// Made the default sender token at startup, when set.
    pub default_sender_token: Option<String>,
    /// Made the default consumer token at startup, when set.
    pub default_consumer_token: Option<String>,
    /// Base URL senders and consumers use, shown in the console.
    pub public_url: Option<String>,
    /// Let the admin console show stored token values, and keep consumer
    /// values so it can. For local development only.
    pub insecure_reveal_tokens: bool,
    pub max_body_bytes: usize,
    /// Upper bound on a consumer's `wait` parameter.
    pub max_wait: Duration,
    pub retention: Retention,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Retention {
    pub max_age: Option<Duration>,
    pub max_events: Option<u64>,
}

impl Retention {
    pub fn is_enabled(&self) -> bool {
        self.max_age.is_some() || self.max_events.is_some()
    }
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let address = |name: &str, default: &str| -> Result<SocketAddr, String> {
            var(name)
                .unwrap_or_else(|| default.into())
                .parse()
                .map_err(|e| format!("{name}: {e}"))
        };
        let max_body_bytes =
            number("HOOKSINK_MAX_BODY_BYTES")?.unwrap_or(DEFAULT_MAX_BODY_BYTES as u64) as usize;
        let max_wait = Duration::from_secs(number("HOOKSINK_MAX_WAIT_SECONDS")?.unwrap_or(60));
        // Zero disables a limit.
        let retention = Retention {
            max_age: number("HOOKSINK_RETENTION_MAX_AGE_SECONDS")?
                .or(Some(7 * 24 * 3600))
                .filter(|&s| s > 0)
                .map(Duration::from_secs),
            max_events: number("HOOKSINK_RETENTION_MAX_EVENTS")?
                .or(Some(100_000))
                .filter(|&n| n > 0),
        };
        Ok(Self {
            listen: address("HOOKSINK_LISTEN", "0.0.0.0:8080")?,
            admin_listen: address("HOOKSINK_ADMIN_LISTEN", "0.0.0.0:8081")?,
            db_path: var("HOOKSINK_DB")
                .unwrap_or_else(|| "/data/events.sqlite".into())
                .into(),
            admin_key: secret("HOOKSINK_ADMIN_KEY")?,
            default_sender_token: secret("HOOKSINK_DEFAULT_SENDER_TOKEN")?,
            default_consumer_token: secret("HOOKSINK_DEFAULT_CONSUMER_TOKEN")?,
            public_url: var("HOOKSINK_PUBLIC_URL"),
            insecure_reveal_tokens: flag("HOOKSINK_INSECURE_REVEAL_TOKENS")?,
            max_body_bytes,
            max_wait,
            retention,
        })
    }
}

fn var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

/// `NAME`, or the trimmed contents of the file at `NAME_FILE`.
fn secret(name: &str) -> Result<Option<String>, String> {
    if let Some(value) = var(name) {
        return Ok(Some(value));
    }
    let file = format!("{name}_FILE");
    let Some(path) = var(&file) else {
        return Ok(None);
    };
    let value = std::fs::read_to_string(&path).map_err(|e| format!("{file} {path}: {e}"))?;
    Ok(Some(value.trim().to_string()).filter(|v| !v.is_empty()))
}

fn flag(name: &str) -> Result<bool, String> {
    match var(name).map(|v| v.to_ascii_lowercase()).as_deref() {
        None | Some("0" | "false" | "no" | "off") => Ok(false),
        Some("1" | "true" | "yes" | "on") => Ok(true),
        Some(other) => Err(format!("{name}: expected true or false, not {other:?}")),
    }
}

fn number(name: &str) -> Result<Option<u64>, String> {
    var(name)
        .map(|v| v.parse().map_err(|e| format!("{name}: {e}")))
        .transpose()
}
