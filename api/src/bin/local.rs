//! Local dev server. Runs the same axum router the Lambda uses, but
//! listens on a real TCP port so you can hit it with curl / the frontend.
//!
//! Run: `cargo run --bin resqd-api-local`  (respects RESQD_* env vars)

use resqd_api::{AppConfig, AppState, router};
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,resqd_api=debug")),
        )
        .init();

    let config = AppConfig::from_env()?;
    let state = Arc::new(AppState::from_config(config).await?);

    let app = router(state);
    let addr: std::net::SocketAddr = std::env::var("RESQD_API_BIND")
        .unwrap_or_else(|_| "127.0.0.1:8787".into())
        .parse()?;

    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("resqd-api listening on http://{addr}");
    axum::serve(listener, app).await?;
    Ok(())
}
