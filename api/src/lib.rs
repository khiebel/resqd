//! RESQD HTTP API.
//!
//! Exposes vault operations (upload, fetch, verify) over HTTP. The same
//! router runs inside AWS Lambda (via `lambda_http`) for production and
//! under a plain `axum::serve` binary for local development. Both binaries
//! live under `src/bin/`.
//!
//! Architecture:
//!
//!   client ─HTTP─▶ router ─▶ AppState ─▶ MultiCloudVault (S3 + GCS)
//!                                    └─▶ CanaryAnchorClient (Base L2)
//!
//! Every successful `GET /vault/{id}` rotates the asset's canary chain and
//! anchors the new commitment on-chain before returning the bytes. This is
//! non-negotiable — it's the core tamper-evidence guarantee.

pub mod auth;
pub mod handlers;
pub mod state;

pub use state::{AppConfig, AppState};

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::http::{HeaderValue, Method};
use axum::routing::{get, post};
use std::sync::Arc;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::trace::TraceLayer;

/// Max request body size. API Gateway HTTP API allows 10 MB and Lambda
/// sync invoke caps at 6 MB, so we bound at 5 MB to leave headroom for
/// headers and the base64 encoding API Gateway applies to binary bodies.
/// Files bigger than this will need presigned S3 uploads (future work).
const MAX_BODY_BYTES: usize = 5 * 1024 * 1024;

/// Build the axum router. Shared by both the Lambda and local binaries.
///
/// CORS is explicit-origin + credentials-enabled (required for the session
/// cookie to cross origin from the frontend Pages deployment to the API
/// Gateway). The allow list comes from `RESQD_CORS_ORIGINS` (comma-
/// separated). If the env var is unset we fall back to a set of known
/// dev/prod origins.
pub fn router(state: Arc<AppState>) -> Router {
    // Build the allow list. `CorsLayer::allow_origin` REPLACES its value
    // each time it's called, so we have to build an `AllowOrigin::list`
    // up front and pass it in a single call — looping with `.allow_origin()`
    // silently drops every origin except the last.
    let origin_values: Vec<HeaderValue> = cors_origins()
        .iter()
        .filter_map(|o| HeaderValue::from_str(o).ok())
        .collect();
    let cors = CorsLayer::new()
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([
            axum::http::header::CONTENT_TYPE,
            axum::http::header::AUTHORIZATION,
            axum::http::header::COOKIE,
        ])
        .allow_credentials(true)
        .allow_origin(AllowOrigin::list(origin_values))
        .expose_headers([
            "x-resqd-canary-sequence".parse().unwrap(),
            "x-resqd-canary-hash".parse().unwrap(),
        ]);

    Router::new()
        .route("/health", get(handlers::health))
        // Auth
        .route("/auth/register/begin", post(auth::register_begin))
        .route("/auth/register/finish", post(auth::register_finish))
        .route("/auth/login/begin", post(auth::login_begin))
        .route("/auth/login/finish", post(auth::login_finish))
        .route("/auth/me", get(auth::me))
        .route("/auth/logout", post(auth::logout))
        .route(
            "/auth/tokens",
            get(auth::list_tokens).post(auth::create_token),
        )
        .route("/auth/tokens/{hash}", axum::routing::delete(auth::revoke_token))
        // Vault
        .route("/vault", get(handlers::list_vault).post(handlers::upload))
        .route("/vault/init", post(handlers::init))
        .route("/vault/{id}/commit", post(handlers::commit))
        .route(
            "/vault/{id}",
            get(handlers::fetch).delete(handlers::delete_asset),
        )
        .route("/vault/{id}/verify", get(handlers::verify))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .with_state(state)
}

/// Parse the allow-list of CORS origins. Env var takes precedence; the
/// fallback covers local dev + the current Pages deployment + the future
/// custom domain so deploys don't break if the env var is forgotten.
fn cors_origins() -> Vec<String> {
    if let Ok(s) = std::env::var("RESQD_CORS_ORIGINS") {
        return s
            .split(',')
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .collect();
    }
    vec![
        "http://localhost:3000".into(),
        "http://127.0.0.1:3000".into(),
        "https://resqd-app.pages.dev".into(),
        "https://app.resqd.ai".into(),
        "https://resqd.ai".into(),
    ]
}
