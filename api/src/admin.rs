//! Admin endpoints for the RESQD control plane.
//!
//! All handlers require the caller to be an authenticated admin user
//! (currently hardcoded to `khiebel@gmail.com`; configurable via
//! `RESQD_ADMIN_EMAILS` env var later). CF Access is the outer gate
//! so these endpoints are never reachable by unauthenticated traffic.
//!
//! The admin API is read-only for now — it surfaces aggregate state
//! that lets the operator understand the system without exposing
//! plaintext or key material. The zero-knowledge boundary is
//! preserved: we show storage_used_bytes and encrypted_meta_b64
//! (opaque blob), never the underlying filenames or file contents.

use crate::auth::AuthUser;
use crate::state::AppState;
use aws_sdk_dynamodb::types::AttributeValue;
use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use std::sync::Arc;
use tracing::info;

// ── Admin gate ──────────────────────────────────────────────────────
//
// Accepts two auth paths so the admin console works regardless of
// how the request arrives:
//
// 1. **Passkey session** (AuthUser) — the browser has a session
//    cookie from a passkey login. The web page on resqd.ai calls
//    api.resqd.ai which is NOT behind CF Access, so no CF headers
//    arrive. The passkey session IS the auth.
//
// 2. **CF Access header** — if the API were behind CF Access (future
//    or direct-to-origin calls), the cf-access-authenticated-user-email
//    header carries the email.
//
// Either path works. The email must be in the admin list.

const ADMIN_EMAILS: &[&str] = &["khiebel@gmail.com"];

fn is_admin(email: &str) -> bool {
    ADMIN_EMAILS.iter().any(|e| *e == email)
}

fn require_admin(user: &Option<AuthUser>) -> Result<String, Response> {
    // Try passkey session first (the normal path from the web UI).
    if let Some(u) = user {
        if is_admin(&u.email) {
            return Ok(u.email.clone());
        }
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "admin access required" })),
        )
            .into_response());
    }
    // No session — reject. CF Access header path removed since
    // api.resqd.ai is not behind CF Access.
    Err((
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({
            "error": "sign in via passkey first, then visit /admin/"
        })),
    )
        .into_response())
}

// ── DTOs ────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct AdminUserRow {
    pub email: String,
    pub user_id: String,
    pub display_name: String,
    pub created_at: u64,
    pub storage_used_bytes: u64,
    pub has_x25519_identity: bool,
}

#[derive(Serialize)]
pub struct AdminUsersResponse {
    pub count: usize,
    pub total_storage_bytes: u64,
    pub users: Vec<AdminUserRow>,
}

#[derive(Serialize)]
pub struct AdminRingRow {
    pub ring_id: String,
    pub name: String,
    pub owner_user_id: String,
    pub created_at: u64,
    pub member_count: usize,
    pub has_estate_trigger: bool,
    pub estate_trigger_type: Option<String>,
    pub last_owner_activity_at: Option<u64>,
}

#[derive(Serialize)]
pub struct AdminRingsResponse {
    pub count: usize,
    pub rings: Vec<AdminRingRow>,
}

#[derive(Serialize)]
pub struct AdminStatsResponse {
    pub user_count: usize,
    pub total_storage_bytes: u64,
    pub ring_count: usize,
    pub total_ring_members: usize,
    pub rings_with_triggers: usize,
}

// ── Handlers ────────────────────────────────────────────────────────

fn take_s(item: &std::collections::HashMap<String, AttributeValue>, key: &str) -> String {
    item.get(key)
        .and_then(|v| v.as_s().ok().cloned())
        .unwrap_or_default()
}

fn take_n(item: &std::collections::HashMap<String, AttributeValue>, key: &str) -> u64 {
    item.get(key)
        .and_then(|v| v.as_n().ok())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

/// `GET /admin/users` — list all registered users with storage usage
/// and identity status. Scans the users table — fine for alpha
/// population, add pagination when user count > 1000.
pub async fn list_users(
    State(state): State<Arc<AppState>>,
    user: Option<AuthUser>,
) -> Result<Json<AdminUsersResponse>, Response> {
    let admin_email = require_admin(&user)?;
    let auth = state.auth.as_ref().ok_or_else(|| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error":"no auth"}))).into_response()
    })?;

    let mut users = Vec::new();
    let mut total_storage: u64 = 0;
    let mut last_key = None;

    loop {
        let mut scan = auth
            .dynamo
            .scan()
            .table_name(&auth.config.users_table);
        if let Some(key) = last_key.take() {
            scan = scan.set_exclusive_start_key(Some(key));
        }
        let out = scan.send().await.map_err(|e| {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response()
        })?;

        for item in out.items() {
            let storage = take_n(item, "storage_used_bytes");
            total_storage += storage;
            users.push(AdminUserRow {
                email: take_s(item, "email"),
                user_id: take_s(item, "user_id"),
                display_name: take_s(item, "display_name"),
                created_at: take_n(item, "created_at"),
                storage_used_bytes: storage,
                has_x25519_identity: item.get("pubkey_x25519_b64").is_some(),
            });
        }

        if out.last_evaluated_key().is_none() {
            break;
        }
        last_key = out.last_evaluated_key().map(|k| k.to_owned());
    }

    users.sort_by(|a, b| b.created_at.cmp(&a.created_at));

    info!(admin = %admin_email, count = users.len(), "admin list_users");

    Ok(Json(AdminUsersResponse {
        count: users.len(),
        total_storage_bytes: total_storage,
        users,
    }))
}

/// `GET /admin/rings` — list all rings with member counts and trigger
/// configs.
pub async fn list_rings(
    State(state): State<Arc<AppState>>,
    user: Option<AuthUser>,
) -> Result<Json<AdminRingsResponse>, Response> {
    let admin_email = require_admin(&user)?;
    let auth = state.auth.as_ref().ok_or_else(|| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error":"no auth"}))).into_response()
    })?;

    // Scan the rings table for META rows.
    let mut rings = Vec::new();
    let mut last_key = None;

    loop {
        let mut scan = auth
            .dynamo
            .scan()
            .table_name(&auth.config.rings_table)
            .filter_expression("sk = :meta")
            .expression_attribute_values(":meta", AttributeValue::S("META".into()));
        if let Some(key) = last_key.take() {
            scan = scan.set_exclusive_start_key(Some(key));
        }
        let out = scan.send().await.map_err(|e| {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response()
        })?;

        for item in out.items() {
            let ring_id = take_s(item, "ring_id");

            // Count members for this ring.
            let members_out = auth
                .dynamo
                .query()
                .table_name(&auth.config.rings_table)
                .key_condition_expression("pk = :pk AND begins_with(sk, :prefix)")
                .expression_attribute_values(
                    ":pk",
                    AttributeValue::S(format!("RING#{ring_id}")),
                )
                .expression_attribute_values(
                    ":prefix",
                    AttributeValue::S("MEMBER#".into()),
                )
                .select(aws_sdk_dynamodb::types::Select::Count)
                .send()
                .await;
            let member_count = members_out.map(|o| o.count() as usize).unwrap_or(0);

            let trigger_json = take_s(item, "estate_trigger");
            let has_trigger = !trigger_json.is_empty();
            let trigger_type = if has_trigger {
                serde_json::from_str::<serde_json::Value>(&trigger_json)
                    .ok()
                    .and_then(|v| v.get("type").and_then(|t| t.as_str()).map(String::from))
            } else {
                None
            };

            rings.push(AdminRingRow {
                ring_id,
                name: take_s(item, "name"),
                owner_user_id: take_s(item, "owner_user_id"),
                created_at: take_n(item, "created_at"),
                member_count,
                has_estate_trigger: has_trigger,
                estate_trigger_type: trigger_type,
                last_owner_activity_at: {
                    let v = take_n(item, "last_owner_activity_at");
                    if v > 0 { Some(v) } else { None }
                },
            });
        }

        if out.last_evaluated_key().is_none() {
            break;
        }
        last_key = out.last_evaluated_key().map(|k| k.to_owned());
    }

    rings.sort_by(|a, b| b.created_at.cmp(&a.created_at));

    info!(admin = %admin_email, count = rings.len(), "admin list_rings");

    Ok(Json(AdminRingsResponse {
        count: rings.len(),
        rings,
    }))
}

/// `POST /admin/rings/{ring_id}/unlock-executor/{user_email}` — manually
/// unlock an executor after the admin has verified proof of death. This
/// is the primary estate trigger mechanism — automatic triggers
/// (inactivity/scheduled) are secondary opt-in fallbacks, not the
/// default.
///
/// The admin clicks this after reviewing a death certificate or
/// equivalent documentation submitted through the heir-claim flow.
/// Sets `estate_unlocked_at` on the executor's membership row so
/// they can unwrap the ring privkey on their next login.
pub async fn unlock_executor(
    State(state): State<Arc<AppState>>,
    user: Option<AuthUser>,
    axum::extract::Path((ring_id, target_email)): axum::extract::Path<(String, String)>,
) -> Result<Json<serde_json::Value>, Response> {
    let admin_email = require_admin(&user)?;
    let auth = state.auth.as_ref().ok_or_else(|| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error":"no auth"}))).into_response()
    })?;

    // Resolve the target user.
    let target_email = target_email.trim().to_ascii_lowercase();
    let target = crate::auth::get_user_by_email(auth, &target_email)
        .await
        .map_err(|e| {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response()
        })?
        .ok_or_else(|| {
            (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "user not found"}))).into_response()
        })?;

    // Verify this user is actually an Executor on this ring.
    let membership = auth
        .dynamo
        .get_item()
        .table_name(&auth.config.rings_table)
        .key("pk", AttributeValue::S(format!("RING#{ring_id}")))
        .key("sk", AttributeValue::S(format!("MEMBER#{}", target.user_id)))
        .send()
        .await
        .map_err(|e| {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response()
        })?;
    let item = membership.item.ok_or_else(|| {
        (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "user is not a member of this ring"}))).into_response()
    })?;
    let role = take_s(&item, "role");
    if role != "executor" {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": format!("user has role '{}', not 'executor'", role)})),
        ).into_response());
    }

    // Check if already unlocked.
    let already = take_n(&item, "estate_unlocked_at");
    if already > 0 {
        return Ok(Json(serde_json::json!({
            "ring_id": ring_id,
            "executor_email": target_email,
            "already_unlocked_at": already,
            "message": "executor was already unlocked"
        })));
    }

    // Set estate_unlocked_at.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    auth.dynamo
        .update_item()
        .table_name(&auth.config.rings_table)
        .key("pk", AttributeValue::S(format!("RING#{ring_id}")))
        .key("sk", AttributeValue::S(format!("MEMBER#{}", target.user_id)))
        .update_expression("SET estate_unlocked_at = :t")
        .expression_attribute_values(":t", AttributeValue::N(now.to_string()))
        .send()
        .await
        .map_err(|e| {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response()
        })?;

    info!(
        admin = %admin_email,
        ring_id = %ring_id,
        executor = %target_email,
        "admin unlocked executor — estate trigger fired manually"
    );

    Ok(Json(serde_json::json!({
        "ring_id": ring_id,
        "executor_email": target_email,
        "unlocked_at": now,
        "message": "executor unlocked — they can now access ring assets on next login"
    })))
}

/// `GET /admin/stats` — aggregate system stats.
pub async fn stats(
    State(state): State<Arc<AppState>>,
    user: Option<AuthUser>,
) -> Result<Json<AdminStatsResponse>, Response> {
    let admin_email = require_admin(&user)?;
    let auth = state.auth.as_ref().ok_or_else(|| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error":"no auth"}))).into_response()
    })?;

    // User count + total storage.
    let users_scan = auth
        .dynamo
        .scan()
        .table_name(&auth.config.users_table)
        .select(aws_sdk_dynamodb::types::Select::AllAttributes)
        .send()
        .await
        .map_err(|e| {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response()
        })?;
    let user_count = users_scan.count() as usize;
    let total_storage: u64 = users_scan
        .items()
        .iter()
        .map(|item| take_n(item, "storage_used_bytes"))
        .sum();

    // Ring stats — scan META rows only.
    let rings_scan = auth
        .dynamo
        .scan()
        .table_name(&auth.config.rings_table)
        .filter_expression("sk = :meta")
        .expression_attribute_values(":meta", AttributeValue::S("META".into()))
        .send()
        .await
        .map_err(|e| {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response()
        })?;
    let ring_count = rings_scan.count() as usize;
    let rings_with_triggers = rings_scan
        .items()
        .iter()
        .filter(|item| item.get("estate_trigger").is_some())
        .count();

    // Total ring members — scan MEMBER# rows.
    let members_scan = auth
        .dynamo
        .scan()
        .table_name(&auth.config.rings_table)
        .filter_expression("begins_with(sk, :prefix)")
        .expression_attribute_values(":prefix", AttributeValue::S("MEMBER#".into()))
        .select(aws_sdk_dynamodb::types::Select::Count)
        .send()
        .await
        .map_err(|e| {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response()
        })?;
    let total_ring_members = members_scan.count() as usize;

    info!(admin = %admin_email, "admin stats");

    Ok(Json(AdminStatsResponse {
        user_count,
        total_storage_bytes: total_storage,
        ring_count,
        total_ring_members,
        rings_with_triggers,
    }))
}
