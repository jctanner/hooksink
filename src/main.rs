use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use tokio::net::TcpListener;
use tokio::sync::watch;

use webhook_sink_service::admin::{self, AdminState};
use webhook_sink_service::api::{self, AppState, Settings};
use webhook_sink_service::config::{Config, Retention};
use webhook_sink_service::store::{EventStore, SqliteStore};
use webhook_sink_service::tokens::{DefaultToken, TokenKind, TokenStore};

const RETENTION_INTERVAL: Duration = Duration::from_secs(60);
/// Shorter values are accepted but warned about.
const MIN_DEFAULT_TOKEN_LENGTH: usize = 24;

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("webhook-sink: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), String> {
    let config = Config::from_env()?;
    if let Some(parent) = config.db_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
    }
    let store = Arc::new(
        SqliteStore::open(&config.db_path)
            .map_err(|e| format!("{}: {e}", config.db_path.display()))?
            .keep_consumer_values(config.insecure_reveal_tokens),
    );
    if config.insecure_reveal_tokens {
        eprintln!(
            "warning: insecure reveal mode: the admin console can show token values, \
             and consumer token values are stored"
        );
    } else {
        // Secure mode stores consumer values as fingerprints only, so drop
        // any kept while reveal mode was on.
        let forgotten = store
            .forget_consumer_values()
            .map_err(|e| format!("forgetting consumer token values: {e}"))?;
        if forgotten > 0 {
            eprintln!("reveal mode is off: forgot {forgotten} stored consumer token values");
        }
    }
    let events: Arc<dyn EventStore> = store.clone();
    let tokens: Arc<dyn TokenStore> = store;

    for (kind, value, name) in [
        (
            TokenKind::Sender,
            &config.default_sender_token,
            "default-sender",
        ),
        (
            TokenKind::Consumer,
            &config.default_consumer_token,
            "default-consumer",
        ),
    ] {
        if let Some(value) = value {
            ensure_default(tokens.as_ref(), kind, value, name)?;
        }
    }

    if config.retention.is_enabled() {
        tokio::spawn(retention(events.clone(), config.retention));
    }

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let public = api::router(AppState::new(
        events.clone(),
        tokens.clone(),
        Settings::from(&config),
        shutdown_rx.clone(),
    ));
    let listener = TcpListener::bind(config.listen)
        .await
        .map_err(|e| format!("bind {}: {e}", config.listen))?;
    eprintln!(
        "webhook-sink listening on {} (db {})",
        config.listen,
        config.db_path.display()
    );
    let public = tokio::spawn(
        axum::serve(listener, public)
            .with_graceful_shutdown(wait_for(shutdown_rx.clone()))
            .into_future(),
    );

    let admin = match &config.admin_key {
        Some(key) => {
            let app = admin::router(AdminState::new(
                events,
                tokens,
                key.clone(),
                config.public_url.clone(),
                config.insecure_reveal_tokens,
            ));
            let listener = TcpListener::bind(config.admin_listen)
                .await
                .map_err(|e| format!("bind {}: {e}", config.admin_listen))?;
            eprintln!("webhook-sink admin console on {}", config.admin_listen);
            Some(tokio::spawn(
                axum::serve(listener, app)
                    .with_graceful_shutdown(wait_for(shutdown_rx))
                    .into_future(),
            ))
        }
        None => {
            eprintln!("webhook-sink admin console disabled: no WEBHOOK_SINK_ADMIN_KEY");
            None
        }
    };

    tokio::spawn(async move {
        shutdown_signal().await;
        // Release waiting long-polls so shutdown is not held for `wait`.
        shutdown_tx.send_replace(true);
    });

    let joined = |r: Result<std::io::Result<()>, tokio::task::JoinError>| match r {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(e.to_string()),
        Err(e) => Err(e.to_string()),
    };
    joined(public.await)?;
    if let Some(admin) = admin {
        joined(admin.await)?;
    }
    Ok(())
}

fn ensure_default(
    tokens: &dyn TokenStore,
    kind: TokenKind,
    value: &str,
    name: &str,
) -> Result<(), String> {
    if value.len() < MIN_DEFAULT_TOKEN_LENGTH {
        eprintln!(
            "warning: the default {kind} token is shorter than {MIN_DEFAULT_TOKEN_LENGTH} characters"
        );
    }
    match tokens
        .ensure_default(kind, value, name, Utc::now().timestamp_millis())
        .map_err(|e| format!("default {kind} token: {e}"))?
    {
        DefaultToken::Created(t) => eprintln!("created default {kind} token {}", t.id),
        DefaultToken::Existing(t) => eprintln!("default {kind} token {}", t.id),
        DefaultToken::Revoked(t) => eprintln!(
            "warning: the configured default {kind} token {} is revoked and stays revoked; \
             replace the value in the deployment secret",
            t.id
        ),
    }
    Ok(())
}

async fn wait_for(mut shutdown: watch::Receiver<bool>) {
    let _ = shutdown.wait_for(|stop| *stop).await;
}

async fn retention(events: Arc<dyn EventStore>, retention: Retention) {
    let mut interval = tokio::time::interval(RETENTION_INTERVAL);
    loop {
        interval.tick().await;
        let cutoff = retention
            .max_age
            .map(|age| Utc::now().timestamp_millis() - age.as_millis() as i64);
        let events = events.clone();
        match tokio::task::spawn_blocking(move || events.trim(cutoff, retention.max_events)).await {
            Ok(Ok(0)) => {}
            Ok(Ok(deleted)) => eprintln!("retention removed {deleted} events"),
            Ok(Err(e)) => eprintln!("retention: {e}"),
            Err(e) => eprintln!("retention: {e}"),
        }
    }
}

async fn shutdown_signal() {
    let interrupt = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("install SIGTERM handler");
        tokio::select! {
            _ = interrupt => {}
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    let _ = interrupt.await;
}
