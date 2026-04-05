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

pub mod handlers;
pub mod state;

pub use state::{AppConfig, AppState};

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post};
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

/// Max request body size. API Gateway HTTP API allows 10 MB and Lambda
/// sync invoke caps at 6 MB, so we bound at 5 MB to leave headroom for
/// headers and the base64 encoding API Gateway applies to binary bodies.
/// Files bigger than this will need presigned S3 uploads (future work).
const MAX_BODY_BYTES: usize = 5 * 1024 * 1024;

/// Build the axum router. Shared by both the Lambda and local binaries.
///
/// CORS is permissive (any origin, any method) for the alpha. When we front
/// the endpoint with Cloudflare Access and move past MVP, lock this down to
/// the specific allowed origins (e.g. `https://resqd.ai`).
pub fn router(state: Arc<AppState>) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any)
        .expose_headers([
            "x-resqd-canary-sequence".parse().unwrap(),
            "x-resqd-canary-hash".parse().unwrap(),
        ]);

    Router::new()
        .route("/health", get(handlers::health))
        .route("/vault", post(handlers::upload))
        .route("/vault/init", post(handlers::init))
        .route("/vault/{id}/commit", post(handlers::commit))
        .route("/vault/{id}", get(handlers::fetch))
        .route("/vault/{id}/verify", get(handlers::verify))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .with_state(state)
}
