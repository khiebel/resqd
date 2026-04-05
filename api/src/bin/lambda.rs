//! AWS Lambda entry point. Uses `lambda_http` to adapt API Gateway HTTP API
//! events into the shared axum router. Deployed as an ARM64 Rust binary on
//! `provided.al2023`.

use lambda_http::{Error, run};
use resqd_api::{AppConfig, AppState, router};
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with_target(false)
        .without_time()
        .json()
        .init();

    let config = AppConfig::from_env().map_err(|e| -> Error { format!("config: {e}").into() })?;
    let state = Arc::new(
        AppState::from_config(config)
            .await
            .map_err(|e| -> Error { format!("state: {e}").into() })?,
    );

    let app = router(state);
    run(app).await
}
