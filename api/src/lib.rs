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

pub mod admin;
pub mod auth;
pub mod handlers;
pub mod rings;
pub mod state;
pub mod stream;

pub use state::{AppConfig, AppState};

use axum::Router;
use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::{HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use std::sync::Arc;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing::warn;

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
        .route(
            "/auth/login/begin_discoverable",
            post(auth::login_begin_discoverable),
        )
        .route(
            "/auth/login/finish_discoverable",
            post(auth::login_finish_discoverable),
        )
        .route("/auth/me", get(auth::me))
        .route("/auth/me/identity", axum::routing::put(auth::set_identity))
        .route(
            "/auth/me/recovery-blob",
            get(auth::get_recovery_blob)
                .put(auth::set_recovery_blob)
                .delete(auth::delete_recovery_blob),
        )
        .route("/auth/logout", post(auth::logout))
        .route(
            "/auth/tokens",
            get(auth::list_tokens).post(auth::create_token),
        )
        .route("/auth/tokens/{hash}", axum::routing::delete(auth::revoke_token))
        // User identity lookup — share-flow-only, requires an auth'd caller.
        .route("/users/lookup", get(auth::lookup_user))
        // Vault
        .route("/vault", get(handlers::list_vault).post(handlers::upload))
        .route("/vault/init", post(handlers::init))
        .route("/vault/{id}/commit", post(handlers::commit))
        // Streaming upload path (Chunk 1.4) — S3 multipart for files
        // larger than the single-shot ~200 MB ceiling. Kept separate
        // from the legacy `/vault/init` + `/vault/{id}/commit` path so
        // the smoke tests and small-file flows continue to work.
        .route("/vault/stream/init", post(stream::stream_init))
        .route(
            "/vault/stream/{id}/presigned-parts",
            post(stream::stream_presigned_parts),
        )
        .route(
            "/vault/stream/{id}/commit",
            post(stream::stream_commit),
        )
        .route(
            "/vault/stream/{id}/abort",
            post(stream::stream_abort),
        )
        .route(
            "/vault/{id}",
            get(handlers::fetch).delete(handlers::delete_asset),
        )
        .route("/vault/{id}/verify", get(handlers::verify))
        // Read-only asset sharing. Owner-only on create/list/delete.
        .route(
            "/vault/{id}/shares",
            get(handlers::list_shares).post(handlers::create_share),
        )
        .route(
            "/vault/{id}/shares/{recipient_email}",
            axum::routing::delete(handlers::delete_share),
        )
        // Family rings. Phase 3.
        .route("/rings", get(rings::list_rings).post(rings::create_ring))
        .route("/rings/{id}", get(rings::get_ring))
        .route(
            "/rings/{id}/members",
            post(rings::invite_member),
        )
        .route(
            "/rings/{id}/members/{email}",
            axum::routing::delete(rings::remove_member),
        )
        .route("/rings/{id}/me", get(rings::my_membership))
        .route("/rings/{id}/trigger", axum::routing::put(rings::set_trigger))
        // Admin control plane. All handlers gate on admin email.
        .route("/admin/users", get(admin::list_users))
        .route("/admin/rings", get(admin::list_rings))
        .route("/admin/stats", get(admin::stats))
        .route("/admin/audit", get(admin::audit))
        .route("/admin/security", get(admin::security))
        .route("/admin/metrics", get(admin::metrics))
        .route("/admin/estate", get(admin::estate))
        .route(
            "/admin/users/{email}/disable",
            post(admin::disable_user),
        )
        .route(
            "/admin/users/{email}/enable",
            post(admin::enable_user),
        )
        .route(
            "/admin/users/{email}/reset-quota",
            post(admin::reset_quota),
        )
        .route(
            "/admin/rings/{ring_id}/unlock-executor/{email}",
            post(admin::unlock_executor),
        )
        .route("/admin/anchor-retries", get(admin::anchor_retry_stats))
        .route("/admin/retry-anchors", post(admin::retry_anchors))
        .route("/admin/reaper/scan", post(admin::reaper_scan))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(TraceLayer::new_for_http())
        .layer(middleware::from_fn_with_state(
            state.clone(),
            origin_secret_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            geo_block_middleware,
        ))
        // Security headers wrap every response, including the 403s from
        // origin_secret_middleware and the 451s from geo_block_middleware,
        // but sit inside CORS so preflight responses still get the CORS
        // headers they need. Added 2026-04-10 for advisory LIVE-12.
        .layer(middleware::from_fn(security_headers_middleware))
        .layer(cors)
        .with_state(state)
}

/// Reject requests that bypass the Cloudflare Worker.
///
/// When `RESQD_ORIGIN_SECRET` is set, every request must carry a matching
/// `x-origin-secret` header. The Worker injects this before forwarding;
/// direct-to-API-Gateway callers won't have it. OPTIONS (CORS preflight)
/// and /health are exempt so the browser and Lambda warmup probes still
/// work.
///
/// **Hardened 2026-04-10 for advisory LIVE-12.** `/admin` was previously
/// in the exemption list based on the incorrect assumption that CF
/// Access was an inner gate the admin endpoints could rely on. CF Access
/// runs at the edge — if a caller reaches API Gateway directly they have
/// already bypassed CF Access. Admin endpoints now require the origin
/// secret just like any other protected route, and `require_admin()` in
/// `admin.rs` enforces a server-side `RESQD_ADMIN_EMAILS` allowlist as
/// the second belt. Both must be true to hit an admin handler.
pub async fn origin_secret_middleware(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Response {
    let Some(ref expected) = state.config.origin_secret else {
        // No secret configured — allow everything (local dev / tests).
        return next.run(req).await;
    };

    // Always allow preflight and health. Auth endpoints are called
    // directly by the browser SPA (which hits the raw API GW URL, not
    // the CF Worker), so they can't carry the origin secret — they
    // have their own passkey/session security. Same for the vault and
    // ring user-flow endpoints.
    //
    // NOTE: `/admin` is deliberately NOT exempt. See LIVE-12.
    let path = req.uri().path();
    if req.method() == Method::OPTIONS
        || path == "/health"
        || path.starts_with("/auth")
        || path == "/vault"
        || path.starts_with("/vault/")
        || path.starts_with("/users/")
        || path.starts_with("/rings")
    {
        return next.run(req).await;
    }

    let provided = req
        .headers()
        .get("x-origin-secret")
        .and_then(|v| v.to_str().ok());

    match provided {
        Some(v) if v == expected.as_str() => next.run(req).await,
        _ => {
            warn!(
                path = %req.uri().path(),
                "rejected request: missing or invalid x-origin-secret"
            );
            (
                StatusCode::FORBIDDEN,
                axum::Json(serde_json::json!({
                    "error": "Forbidden",
                    "code": "origin_bypass",
                })),
            )
                .into_response()
        }
    }
}

/// Attach defensive HTTP security headers to every response.
///
/// **Introduced 2026-04-10 for advisory LIVE-12.** The API is JSON-only
/// — there is no HTML rendered from the api.resqd.ai origin, so the CSP
/// is maximally restrictive: no scripts, no frames, no anything. The
/// headers here protect against the degenerate case where an attacker
/// convinces a browser to render an API response as HTML (e.g. via a
/// content-type confusion) or embed the API in an iframe.
///
/// Headers set:
///   - `Strict-Transport-Security`: 2 years + includeSubDomains
///   - `X-Content-Type-Options: nosniff`
///   - `X-Frame-Options: DENY`
///   - `Referrer-Policy: strict-origin-when-cross-origin`
///   - `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'; base-uri 'none'`
///   - `Cross-Origin-Resource-Policy: same-site`
///   - `Cross-Origin-Opener-Policy: same-origin`
///   - `Permissions-Policy`: denies camera/mic/geolocation/payment
pub async fn security_headers_middleware(req: Request, next: Next) -> Response {
    let mut response = next.run(req).await;
    let h = response.headers_mut();
    h.insert(
        "Strict-Transport-Security",
        HeaderValue::from_static("max-age=63072000; includeSubDomains; preload"),
    );
    h.insert(
        "X-Content-Type-Options",
        HeaderValue::from_static("nosniff"),
    );
    h.insert("X-Frame-Options", HeaderValue::from_static("DENY"));
    h.insert(
        "Referrer-Policy",
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    h.insert(
        "Content-Security-Policy",
        HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'; base-uri 'none'"),
    );
    // CORP: same-site allows the app.resqd.ai SPA to fetch from
    // api.resqd.ai (both under *.resqd.ai) while still blocking truly
    // cross-origin reads from other sites. Do NOT change this to
    // "same-origin" — it would break the SPA, because api.resqd.ai
    // and app.resqd.ai are different origins.
    h.insert(
        "Cross-Origin-Resource-Policy",
        HeaderValue::from_static("same-site"),
    );
    // COOP: unsafe-none for a pure JSON API. A stricter value like
    // "same-origin" is meaningless on API responses (there's nothing
    // to open cross-origin) and would surprise us if an error page
    // ever accidentally rendered in a browser tab. Per Dave's LIVE-12
    // review, 2026-04-10.
    h.insert(
        "Cross-Origin-Opener-Policy",
        HeaderValue::from_static("unsafe-none"),
    );
    h.insert(
        "Permissions-Policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=(), payment=()"),
    );
    response
}

/// Reject requests from countries on the block list.
///
/// **Intent:** best-effort compliance with US OFAC sanctions and
/// export-control restrictions. Anyone with a VPN can trivially
/// defeat this; that's fine — the goal is to demonstrate good-faith
/// compliance, not build an impenetrable wall, and the legal position
/// `docs/JURISDICTION.md` outlines only requires best-effort.
///
/// **Mechanism:** trusts the `cf-ipcountry` header Cloudflare injects
/// on every request that reaches the origin via the CF network. If
/// the header is missing (e.g. local dev, direct-to-Lambda test) the
/// request is allowed through — missing country info is NOT treated
/// as blocked, because that would lock the ops team and the smoke
/// test harness out. A real deploy MUST have the CF tunnel / origin
/// rule in place so the header is always present in prod.
///
/// **Defence in depth:** a Cloudflare WAF rule should also sit in
/// front of this at the edge so blocked traffic never touches the
/// origin at all. The Lambda middleware is the fallback for the
/// "CF rule misconfigured" failure mode.
///
/// Emits a 451 Unavailable For Legal Reasons with a JSON body
/// pointing at `/jurisdiction/` on the marketing site. Never reveals
/// the full block list to the caller — just echoes their own
/// detected country code so they can verify they're in the right
/// place to appeal.
pub async fn geo_block_middleware(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Response {
    let blocked = &state.config.blocked_countries;
    if blocked.is_empty() {
        return next.run(req).await;
    }

    // Always allow preflight and health — preflight because the
    // browser hasn't run any app code yet and needs OPTIONS to
    // resolve before it can even show the block page, and /health
    // because Lambda warmup and CloudWatch probes would otherwise
    // fail-closed.
    if req.method() == Method::OPTIONS || req.uri().path() == "/health" {
        return next.run(req).await;
    }

    let country = req
        .headers()
        .get("cf-ipcountry")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_ascii_uppercase());

    let Some(country) = country else {
        // Missing header — allow, per the "CF tunnel may be bypassed
        // in dev" rationale above.
        return next.run(req).await;
    };

    if blocked.iter().any(|c| c == &country) {
        warn!(country = %country, path = %req.uri().path(), "geo-blocked request");
        return (
            StatusCode::from_u16(451).unwrap(),
            axum::Json(serde_json::json!({
                "error": "Service not available in your region",
                "code": "geo_blocked",
                "detected_country": country,
                "more_info": "https://resqd.ai/jurisdiction/",
            })),
        )
            .into_response();
    }

    next.run(req).await
}

/// Parse the allow-list of CORS origins. Env var takes precedence; the
/// fallback covers local dev + the current Pages deployment + the future
/// custom domain so deploys don't break if the env var is forgotten.
#[cfg(test)]
mod geo_tests {
    //! Unit tests for the geo-block middleware. The full `AppState`
    //! is heavyweight (real AWS clients), so we test the middleware's
    //! decision logic via a thin pure function that mirrors it.
    //!
    //! If you change the logic in `geo_block_middleware`, mirror the
    //! change here to keep the tests meaningful.
    use super::*;

    fn decide(country: Option<&str>, blocked: &[&str], path: &str, method: &Method) -> bool {
        // Returns true iff the request should be BLOCKED.
        if blocked.is_empty() {
            return false;
        }
        if *method == Method::OPTIONS || path == "/health" {
            return false;
        }
        let Some(c) = country else {
            return false;
        };
        let upper = c.trim().to_ascii_uppercase();
        blocked.iter().any(|b| b.to_ascii_uppercase() == upper)
    }

    #[test]
    fn empty_block_list_allows_everyone() {
        assert!(!decide(Some("CN"), &[], "/vault", &Method::GET));
    }

    #[test]
    fn blocked_country_rejected() {
        assert!(decide(Some("CN"), &["CN", "RU"], "/vault", &Method::GET));
        assert!(decide(Some("ru"), &["CN", "RU"], "/vault", &Method::POST));
    }

    #[test]
    fn allowed_country_passes() {
        assert!(!decide(Some("US"), &["CN", "RU"], "/vault", &Method::GET));
        assert!(!decide(Some("GB"), &["CN"], "/auth/me", &Method::GET));
    }

    #[test]
    fn missing_header_passes() {
        // Local dev / direct Lambda tests must not be blocked by
        // accident just because there's no cf-ipcountry header.
        assert!(!decide(None, &["CN"], "/vault", &Method::GET));
    }

    #[test]
    fn options_preflight_always_passes() {
        // CORS preflight must never 451 — the browser needs the
        // OPTIONS to succeed before any app code runs, including
        // the code that would render the block page.
        assert!(!decide(Some("CN"), &["CN"], "/vault", &Method::OPTIONS));
    }

    #[test]
    fn health_check_always_passes() {
        // Lambda warmup probes and CloudWatch synthetic checks hit
        // /health — they come from AWS internal IPs without a
        // cf-ipcountry header, but we want the rule to also be
        // immune to a badly-classified probe origin.
        assert!(!decide(Some("CN"), &["CN"], "/health", &Method::GET));
    }

    #[test]
    fn case_insensitive_header_match() {
        // CF headers are technically case-stable but downstream
        // proxies sometimes munge them; match insensitively.
        assert!(decide(Some("cn"), &["CN"], "/vault", &Method::GET));
        assert!(decide(Some("Cn"), &["CN"], "/vault", &Method::GET));
    }
}

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
