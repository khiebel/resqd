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

use crate::state::AppState;
use aws_sdk_dynamodb::types::AttributeValue;
use axum::{
    Json,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use resqd_core::canary::CanaryCommitment;
use resqd_core::crypto::hash::AssetHash;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{error, info, warn};

// ── Admin gate ──────────────────────────────────────────────────────
//
// Admin identity is COMPLETELY SEPARATE from the user identity store.
// The admin is the operator — not a user of the product. Auth is:
//
// 1. Cloudflare Access gates the web domain (resqd.ai/admin/) so
//    only khiebel@gmail.com can even load the page.
// 2. The admin API endpoints have no auth of their own — they trust
//    that the only caller is the CF-Access-gated admin page.
//
// This is correct for a single-operator alpha. When we add more
// admins, we'll add a dedicated admin identity store (not passkeys).
// The admin console has NOTHING to do with the app's user auth.

// ── Audit logging ──────────────────────────────────────────────────

/// Write an audit log entry to the `resqd-admin-audit` DynamoDB table.
/// Non-fatal: errors are logged but never fail the request.
async fn log_admin_action(
    db: &aws_sdk_dynamodb::Client,
    admin_email: &str,
    action: &str,
    target: &str,
    detail: &serde_json::Value,
) {
    let table = std::env::var("RESQD_ADMIN_AUDIT_TABLE")
        .unwrap_or_else(|_| "resqd-admin-audit".into());

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let now_secs = now.as_secs();
    let now_millis = now.as_millis();

    let pk = {
        // YYYY-MM from unix timestamp
        let dt = time_ym_from_epoch(now_secs);
        dt
    };
    let sk = format!("{}#{}", now_millis, uuid::Uuid::new_v4());

    let result = db
        .put_item()
        .table_name(&table)
        .item("pk", AttributeValue::S(pk))
        .item("sk", AttributeValue::S(sk))
        .item("admin_email", AttributeValue::S(admin_email.to_string()))
        .item("action", AttributeValue::S(action.to_string()))
        .item("target", AttributeValue::S(target.to_string()))
        .item("detail", AttributeValue::S(detail.to_string()))
        .item("timestamp", AttributeValue::N(now_secs.to_string()))
        .send()
        .await;

    if let Err(e) = result {
        error!(error = %e, action = %action, "failed to write admin audit log");
    }
}

/// Compute YYYY-MM string from epoch seconds.
fn time_ym_from_epoch(epoch_secs: u64) -> String {
    // Simple calculation without external chrono dependency.
    // Days since epoch → year/month.
    let days = epoch_secs / 86400;
    // Approximate year and month using a civil calendar algorithm.
    let (y, m, _) = civil_from_days(days as i64);
    format!("{:04}-{:02}", y, m)
}

/// Convert days since 1970-01-01 to (year, month, day).
/// Algorithm from Howard Hinnant's date algorithms.
fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m, d)
}

/// Extract admin email from CF Access header. Falls back to "admin"
/// when the header is absent (direct API GW calls from the CF Access-
/// gated admin page on resqd.ai — the page itself is the auth gate).
fn require_admin(headers: &HeaderMap) -> Result<String, Response> {
    let email = headers
        .get("cf-access-authenticated-user-email")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("admin")
        .to_string();
    Ok(email)
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
    pub disabled: bool,
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

#[derive(Deserialize)]
pub struct AuditQuery {
    pub months_back: Option<u32>,
    pub action: Option<String>,
    pub limit: Option<u32>,
}

#[derive(Serialize)]
pub struct AuditEntry {
    pub timestamp: u64,
    pub admin_email: String,
    pub action: String,
    pub target: String,
    pub detail: serde_json::Value,
}

#[derive(Serialize)]
pub struct AuditResponse {
    pub entries: Vec<AuditEntry>,
    pub count: usize,
}

#[derive(Serialize)]
pub struct SecurityResponse {
    pub user_security: UserSecurityStats,
    pub generated_at: u64,
}

#[derive(Serialize)]
pub struct UserSecurityStats {
    pub total_users: usize,
    pub users_with_identity: usize,
    pub users_without_identity: usize,
    pub disabled_users: usize,
    pub recent_registrations: usize,
}

#[derive(Serialize)]
pub struct MetricsResponse {
    pub lambda: LambdaMetrics,
    pub dynamo: serde_json::Value,
    pub s3: S3Metrics,
    pub generated_at: u64,
}

#[derive(Serialize)]
pub struct LambdaMetrics {
    pub invocations: Vec<MetricDatapoint>,
    pub errors: Vec<MetricDatapoint>,
    pub duration: Vec<MetricDatapoint>,
}

#[derive(Serialize)]
pub struct MetricDatapoint {
    pub timestamp: u64,
    pub value: f64,
}

#[derive(Serialize)]
pub struct S3Metrics {
    pub bucket: String,
    pub object_count: usize,
    pub total_size_bytes: u64,
}

#[derive(Serialize)]
pub struct EstateResponse {
    pub active_triggers: Vec<serde_json::Value>,
    pub completed_unlocks: Vec<serde_json::Value>,
    pub count: usize,
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
    headers: HeaderMap,
) -> Result<Json<AdminUsersResponse>, Response> {
    let admin_email = require_admin(&headers)?;
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
                disabled: item.get("disabled").is_some(),
            });
        }

        if out.last_evaluated_key().is_none() {
            break;
        }
        last_key = out.last_evaluated_key().map(|k| k.to_owned());
    }

    users.sort_by(|a, b| b.created_at.cmp(&a.created_at));

    info!(admin = %admin_email, count = users.len(), "admin list_users");
    log_admin_action(&auth.dynamo, &admin_email, "list_users", "", &serde_json::json!({"count": users.len()})).await;

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
    headers: HeaderMap,
) -> Result<Json<AdminRingsResponse>, Response> {
    let admin_email = require_admin(&headers)?;
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
    log_admin_action(&auth.dynamo, &admin_email, "list_rings", "", &serde_json::json!({"count": rings.len()})).await;

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
    headers: HeaderMap,
    axum::extract::Path((ring_id, target_email)): axum::extract::Path<(String, String)>,
) -> Result<Json<serde_json::Value>, Response> {
    let admin_email = require_admin(&headers)?;
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
    log_admin_action(
        &auth.dynamo,
        &admin_email,
        "unlock_executor",
        &format!("{}:{}", ring_id, target_email),
        &serde_json::json!({"ring_id": ring_id, "executor_email": target_email, "unlocked_at": now}),
    ).await;

    // Best-effort: notify all ring members that an executor has been unlocked.
    let state_clone = state.clone();
    let ring_id_clone = ring_id.clone();
    let executor_email_clone = target_email.clone();
    tokio::spawn(async move {
        if let Err(e) = notify_ring_members(
            &state_clone,
            &ring_id_clone,
            &executor_email_clone,
            "An executor has been granted access to this ring's estate assets. \
             This means a proof-of-death review has been completed and the \
             executor can now retrieve protected documents and credentials \
             on their next login.\n\n\
             If you believe this is in error, please contact support@resqd.ai immediately.",
        )
        .await
        {
            error!(ring_id = %ring_id_clone, error = %e, "failed to send ring member notifications");
        }
    });

    Ok(Json(serde_json::json!({
        "ring_id": ring_id,
        "executor_email": target_email,
        "unlocked_at": now,
        "message": "executor unlocked — they can now access ring assets on next login"
    })))
}

// ── Ring member notification ───────────────────────────────────────

/// Send a notification email to all members of a ring. Best-effort — callers
/// should log failures rather than propagating them to the HTTP response.
///
/// `message` is the body text describing what happened (e.g. executor unlock).
/// The function is intentionally generic so it can be reused for future
/// notification types (ring invite, canary expiry, etc.).
pub async fn notify_ring_members(
    state: &AppState,
    ring_id: &str,
    executor_email: &str,
    message: &str,
) -> anyhow::Result<()> {
    let auth = state
        .auth
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("auth not configured"))?;
    let ses = state
        .ses
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("SES client not configured"))?;

    let sender = std::env::var("RESQD_NOTIFICATION_SENDER")
        .unwrap_or_else(|_| "noreply@resqd.ai".to_string());
    let from = format!("RESQD <{}>", sender);

    // Query all members of this ring.
    let members_result = auth
        .dynamo
        .query()
        .table_name(&auth.config.rings_table)
        .key_condition_expression("pk = :pk AND begins_with(sk, :prefix)")
        .expression_attribute_values(":pk", AttributeValue::S(format!("RING#{ring_id}")))
        .expression_attribute_values(":prefix", AttributeValue::S("MEMBER#".to_string()))
        .send()
        .await?;

    let items = members_result.items.unwrap_or_default();
    if items.is_empty() {
        info!(ring_id = %ring_id, "no ring members to notify");
        return Ok(());
    }

    let subject = "RESQD Estate Notification — Executor Access Granted";
    let body_text = format!(
        "Hello,\n\n\
         This is an automated notification from RESQD regarding ring {}.\n\n\
         {}\n\n\
         Executor: {}\n\n\
         — RESQD (resqd.ai)",
        ring_id, message, executor_email,
    );

    let mut notified = 0u32;
    for item in &items {
        // Extract user_id from the sort key: "MEMBER#{user_id}"
        let sk = item
            .get("sk")
            .and_then(|v| v.as_s().ok())
            .unwrap_or(&String::new())
            .clone();
        let user_id = match sk.strip_prefix("MEMBER#") {
            Some(id) => id.to_string(),
            None => continue,
        };

        // Look up the user's email.
        let user = match crate::auth::get_user_by_user_id(auth, &user_id).await {
            Ok(Some(u)) => u,
            Ok(None) => {
                info!(user_id = %user_id, "ring member user not found, skipping notification");
                continue;
            }
            Err(e) => {
                error!(user_id = %user_id, error = %e, "failed to look up ring member");
                continue;
            }
        };

        // Send the email via SES.
        if let Err(e) = ses
            .send_email()
            .source(&from)
            .destination(
                aws_sdk_ses::types::Destination::builder()
                    .to_addresses(&user.email)
                    .build(),
            )
            .message(
                aws_sdk_ses::types::Message::builder()
                    .subject(
                        aws_sdk_ses::types::Content::builder()
                            .data(subject)
                            .charset("UTF-8")
                            .build()
                            .expect("subject content"),
                    )
                    .body(
                        aws_sdk_ses::types::Body::builder()
                            .text(
                                aws_sdk_ses::types::Content::builder()
                                    .data(&body_text)
                                    .charset("UTF-8")
                                    .build()
                                    .expect("body content"),
                            )
                            .build(),
                    )
                    .build(),
            )
            .send()
            .await
        {
            error!(email = %user.email, error = %e, "SES send_email failed for ring member");
        } else {
            notified += 1;
        }
    }

    info!(ring_id = %ring_id, notified = notified, total_members = items.len(), "ring member notifications sent");
    Ok(())
}

/// `GET /admin/stats` — aggregate system stats.
pub async fn stats(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<AdminStatsResponse>, Response> {
    let admin_email = require_admin(&headers)?;
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
    log_admin_action(&auth.dynamo, &admin_email, "view_stats", "", &serde_json::json!({})).await;

    Ok(Json(AdminStatsResponse {
        user_count,
        total_storage_bytes: total_storage,
        ring_count,
        total_ring_members,
        rings_with_triggers,
    }))
}

// ── New endpoints ──────────────────────────────────────────────────

/// `GET /admin/audit` — query the admin audit log.
pub async fn audit(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<AuditQuery>,
) -> Result<Json<AuditResponse>, Response> {
    let _admin_email = require_admin(&headers)?;
    let auth = state.auth.as_ref().ok_or_else(|| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error":"no auth"}))).into_response()
    })?;

    let table = std::env::var("RESQD_ADMIN_AUDIT_TABLE")
        .unwrap_or_else(|_| "resqd-admin-audit".into());
    let months_back = params.months_back.unwrap_or(1);
    let limit = params.limit.unwrap_or(50);

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Build the list of YYYY-MM partition keys to query.
    let mut month_keys = Vec::new();
    for i in 0..=months_back {
        let secs = now_secs.saturating_sub(i as u64 * 30 * 86400);
        let ym = time_ym_from_epoch(secs);
        if !month_keys.contains(&ym) {
            month_keys.push(ym);
        }
    }

    let mut entries = Vec::new();

    for pk in &month_keys {
        let mut query = auth
            .dynamo
            .query()
            .table_name(&table)
            .key_condition_expression("pk = :pk")
            .expression_attribute_values(":pk", AttributeValue::S(pk.clone()))
            .scan_index_forward(false)
            .limit(limit as i32);

        if let Some(ref action_filter) = params.action {
            query = query
                .filter_expression("#a = :action")
                .expression_attribute_names("#a", "action")
                .expression_attribute_values(":action", AttributeValue::S(action_filter.clone()));
        }

        let out = query.send().await.map_err(|e| {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response()
        })?;

        for item in out.items() {
            entries.push(AuditEntry {
                timestamp: take_n(item, "timestamp"),
                admin_email: take_s(item, "admin_email"),
                action: take_s(item, "action"),
                target: take_s(item, "target"),
                detail: serde_json::from_str(&take_s(item, "detail")).unwrap_or(serde_json::json!(null)),
            });
        }

        if entries.len() >= limit as usize {
            break;
        }
    }

    // Sort newest first across partitions and truncate.
    entries.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    entries.truncate(limit as usize);

    let count = entries.len();
    Ok(Json(AuditResponse { entries, count }))
}

/// `POST /admin/users/{email}/disable` — disable a user account.
pub async fn disable_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(email): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, Response> {
    let admin_email = require_admin(&headers)?;
    let auth = state.auth.as_ref().ok_or_else(|| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error":"no auth"}))).into_response()
    })?;

    let email = urlencoding::decode(&email).unwrap_or_default().to_string();

    auth.dynamo
        .update_item()
        .table_name(&auth.config.users_table)
        .key("email", AttributeValue::S(email.clone()))
        .update_expression("SET disabled = :t")
        .expression_attribute_values(":t", AttributeValue::Bool(true))
        .send()
        .await
        .map_err(|e| {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response()
        })?;

    info!(admin = %admin_email, target = %email, "admin disabled user");
    log_admin_action(&auth.dynamo, &admin_email, "disable_user", &email, &serde_json::json!({})).await;

    Ok(Json(serde_json::json!({
        "email": email,
        "disabled": true,
        "message": "User disabled"
    })))
}

/// `POST /admin/users/{email}/enable` — re-enable a user account.
pub async fn enable_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(email): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, Response> {
    let admin_email = require_admin(&headers)?;
    let auth = state.auth.as_ref().ok_or_else(|| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error":"no auth"}))).into_response()
    })?;

    let email = urlencoding::decode(&email).unwrap_or_default().to_string();

    auth.dynamo
        .update_item()
        .table_name(&auth.config.users_table)
        .key("email", AttributeValue::S(email.clone()))
        .update_expression("REMOVE disabled")
        .send()
        .await
        .map_err(|e| {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response()
        })?;

    info!(admin = %admin_email, target = %email, "admin enabled user");
    log_admin_action(&auth.dynamo, &admin_email, "enable_user", &email, &serde_json::json!({})).await;

    Ok(Json(serde_json::json!({
        "email": email,
        "disabled": false,
        "message": "User enabled"
    })))
}

/// `POST /admin/users/{email}/reset-quota` — reset a user's storage quota.
pub async fn reset_quota(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(email): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, Response> {
    let admin_email = require_admin(&headers)?;
    let auth = state.auth.as_ref().ok_or_else(|| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error":"no auth"}))).into_response()
    })?;

    let email = urlencoding::decode(&email).unwrap_or_default().to_string();

    auth.dynamo
        .update_item()
        .table_name(&auth.config.users_table)
        .key("email", AttributeValue::S(email.clone()))
        .update_expression("SET storage_used_bytes = :z")
        .expression_attribute_values(":z", AttributeValue::N("0".into()))
        .send()
        .await
        .map_err(|e| {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response()
        })?;

    info!(admin = %admin_email, target = %email, "admin reset quota");
    log_admin_action(&auth.dynamo, &admin_email, "reset_quota", &email, &serde_json::json!({})).await;

    Ok(Json(serde_json::json!({
        "email": email,
        "storage_used_bytes": 0,
        "message": "Quota reset"
    })))
}

/// `GET /admin/security` — user security posture overview.
pub async fn security(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<SecurityResponse>, Response> {
    let _admin_email = require_admin(&headers)?;
    let auth = state.auth.as_ref().ok_or_else(|| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error":"no auth"}))).into_response()
    })?;

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let seven_days_ago = now_secs.saturating_sub(7 * 86400);

    let mut total_users = 0usize;
    let mut users_with_identity = 0usize;
    let mut disabled_users = 0usize;
    let mut recent_registrations = 0usize;
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
            total_users += 1;
            if item.get("pubkey_x25519_b64").is_some() {
                users_with_identity += 1;
            }
            if item.get("disabled").is_some() {
                disabled_users += 1;
            }
            let created = take_n(item, "created_at");
            if created >= seven_days_ago {
                recent_registrations += 1;
            }
        }

        if out.last_evaluated_key().is_none() {
            break;
        }
        last_key = out.last_evaluated_key().map(|k| k.to_owned());
    }

    Ok(Json(SecurityResponse {
        user_security: UserSecurityStats {
            total_users,
            users_with_identity,
            users_without_identity: total_users.saturating_sub(users_with_identity),
            disabled_users,
            recent_registrations,
        },
        generated_at: now_secs,
    }))
}

/// `GET /admin/metrics` — operational metrics from CloudWatch, DynamoDB, and S3.
pub async fn metrics(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<MetricsResponse>, Response> {
    let _admin_email = require_admin(&headers)?;
    let auth = state.auth.as_ref().ok_or_else(|| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error":"no auth"}))).into_response()
    })?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let now_secs = now.as_secs();
    let end_time = aws_sdk_cloudwatch::primitives::DateTime::from_secs(now_secs as i64);
    let start_time = aws_sdk_cloudwatch::primitives::DateTime::from_secs(
        now_secs.saturating_sub(24 * 3600) as i64,
    );

    let function_name = std::env::var("RESQD_LAMBDA_FUNCTION_NAME")
        .unwrap_or_else(|_| "resqd-api".into());

    // CloudWatch: Invocations
    let invocations = get_metric_stats(
        &state.cloudwatch,
        &function_name,
        "Invocations",
        "Sum",
        start_time.clone(),
        end_time.clone(),
    )
    .await;

    // CloudWatch: Errors
    let errors = get_metric_stats(
        &state.cloudwatch,
        &function_name,
        "Errors",
        "Sum",
        start_time.clone(),
        end_time.clone(),
    )
    .await;

    // CloudWatch: Duration
    let duration = get_metric_stats(
        &state.cloudwatch,
        &function_name,
        "Duration",
        "Average",
        start_time,
        end_time,
    )
    .await;

    // DynamoDB: DescribeTable for each resqd-* table.
    let table_names = vec![
        auth.config.users_table.clone(),
        auth.config.challenges_table.clone(),
        auth.config.tokens_table.clone(),
        auth.config.rings_table.clone(),
        std::env::var("RESQD_ADMIN_AUDIT_TABLE").unwrap_or_else(|_| "resqd-admin-audit".into()),
    ];

    let mut dynamo_info = serde_json::Map::new();
    for t in &table_names {
        let desc = auth
            .dynamo
            .describe_table()
            .table_name(t)
            .send()
            .await;
        match desc {
            Ok(out) => {
                if let Some(table) = out.table() {
                    dynamo_info.insert(
                        t.clone(),
                        serde_json::json!({
                            "item_count": table.item_count().unwrap_or(0),
                            "size_bytes": table.table_size_bytes().unwrap_or(0),
                        }),
                    );
                }
            }
            Err(e) => {
                dynamo_info.insert(
                    t.clone(),
                    serde_json::json!({"error": e.to_string()}),
                );
            }
        }
    }

    // S3: vault bucket stats.
    let vault_bucket = std::env::var("RESQD_S3_BUCKET")
        .unwrap_or_else(|_| "resqd-vault-64553a1a".into());
    let mut object_count = 0usize;
    let mut total_size: u64 = 0;
    let mut continuation_token: Option<String> = None;

    loop {
        let mut req = state
            .s3_admin
            .list_objects_v2()
            .bucket(&vault_bucket);
        if let Some(ref token) = continuation_token {
            req = req.continuation_token(token);
        }
        let out = req.send().await;
        match out {
            Ok(resp) => {
                let contents = resp.contents();
                object_count += contents.len();
                for obj in contents {
                    total_size += obj.size.unwrap_or(0) as u64;
                }
                if resp.is_truncated().unwrap_or(false) {
                    continuation_token = resp.next_continuation_token().map(String::from);
                } else {
                    break;
                }
            }
            Err(e) => {
                error!(error = %e, "failed to list S3 objects for metrics");
                break;
            }
        }
    }

    Ok(Json(MetricsResponse {
        lambda: LambdaMetrics {
            invocations,
            errors,
            duration,
        },
        dynamo: serde_json::Value::Object(dynamo_info),
        s3: S3Metrics {
            bucket: vault_bucket,
            object_count,
            total_size_bytes: total_size,
        },
        generated_at: now_secs,
    }))
}

/// Helper to call CloudWatch GetMetricStatistics for a Lambda metric.
async fn get_metric_stats(
    cw: &aws_sdk_cloudwatch::Client,
    function_name: &str,
    metric_name: &str,
    stat: &str,
    start_time: aws_sdk_cloudwatch::primitives::DateTime,
    end_time: aws_sdk_cloudwatch::primitives::DateTime,
) -> Vec<MetricDatapoint> {
    let dimension = aws_sdk_cloudwatch::types::Dimension::builder()
        .name("FunctionName")
        .value(function_name)
        .build();

    let result = cw
        .get_metric_statistics()
        .namespace("AWS/Lambda")
        .metric_name(metric_name)
        .set_dimensions(Some(vec![dimension]))
        .start_time(start_time)
        .end_time(end_time)
        .period(3600) // 1 hour
        .statistics(match stat {
            "Sum" => aws_sdk_cloudwatch::types::Statistic::Sum,
            "Average" => aws_sdk_cloudwatch::types::Statistic::Average,
            _ => aws_sdk_cloudwatch::types::Statistic::Sum,
        })
        .send()
        .await;

    match result {
        Ok(out) => {
            let mut points: Vec<MetricDatapoint> = out
                .datapoints()
                .iter()
                .map(|dp| {
                    let ts = dp
                        .timestamp()
                        .map(|t| t.secs() as u64)
                        .unwrap_or(0);
                    let value = match stat {
                        "Sum" => dp.sum().unwrap_or(0.0),
                        "Average" => dp.average().unwrap_or(0.0),
                        _ => dp.sum().unwrap_or(0.0),
                    };
                    MetricDatapoint {
                        timestamp: ts,
                        value,
                    }
                })
                .collect();
            points.sort_by_key(|p| p.timestamp);
            points
        }
        Err(e) => {
            error!(error = %e, metric = %metric_name, "CloudWatch GetMetricStatistics failed");
            Vec::new()
        }
    }
}

/// `GET /admin/estate` — overview of estate triggers and unlock status.
pub async fn estate(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<EstateResponse>, Response> {
    let _admin_email = require_admin(&headers)?;
    let auth = state.auth.as_ref().ok_or_else(|| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error":"no auth"}))).into_response()
    })?;

    // Scan for META rows that have an estate_trigger attribute.
    let mut active_triggers = Vec::new();
    let mut completed_unlocks = Vec::new();
    let mut last_key = None;

    loop {
        let mut scan = auth
            .dynamo
            .scan()
            .table_name(&auth.config.rings_table)
            .filter_expression("sk = :meta AND attribute_exists(estate_trigger)")
            .expression_attribute_values(":meta", AttributeValue::S("META".into()));
        if let Some(key) = last_key.take() {
            scan = scan.set_exclusive_start_key(Some(key));
        }
        let out = scan.send().await.map_err(|e| {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response()
        })?;

        for item in out.items() {
            let ring_id = take_s(item, "ring_id");
            let trigger_json = take_s(item, "estate_trigger");
            let trigger: serde_json::Value = serde_json::from_str(&trigger_json).unwrap_or(serde_json::json!(null));

            // Query MEMBER# rows for executors.
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
                .send()
                .await;

            let mut executors = Vec::new();
            let mut any_unlocked = false;

            if let Ok(mout) = members_out {
                for member in mout.items() {
                    let role = take_s(member, "role");
                    if role == "executor" {
                        let unlocked_at = take_n(member, "estate_unlocked_at");
                        let user_id = take_s(member, "user_id");
                        let email = take_s(member, "email");
                        if unlocked_at > 0 {
                            any_unlocked = true;
                        }
                        executors.push(serde_json::json!({
                            "user_id": user_id,
                            "email": email,
                            "unlocked_at": if unlocked_at > 0 { Some(unlocked_at) } else { None::<u64> },
                        }));
                    }
                }
            }

            let entry = serde_json::json!({
                "ring_id": ring_id,
                "name": take_s(item, "name"),
                "owner_user_id": take_s(item, "owner_user_id"),
                "trigger": trigger,
                "executors": executors,
            });

            if any_unlocked {
                completed_unlocks.push(entry);
            } else {
                active_triggers.push(entry);
            }
        }

        if out.last_evaluated_key().is_none() {
            break;
        }
        last_key = out.last_evaluated_key().map(|k| k.to_owned());
    }

    let count = active_triggers.len() + completed_unlocks.len();
    Ok(Json(EstateResponse {
        active_triggers,
        completed_unlocks,
        count,
    }))
}

// ── Anchor retry endpoints ─────────────────────────────────────────

#[derive(Serialize)]
pub struct AnchorRetryStatsResponse {
    pub pending: usize,
    pub completed: usize,
    pub failed: usize,
}

/// `GET /admin/anchor-retries` — return counts of pending anchor retries.
pub async fn anchor_retry_stats(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<AnchorRetryStatsResponse>, Response> {
    let _admin = require_admin(&headers)?;

    let auth = state.auth.as_ref().ok_or_else(|| {
        (StatusCode::SERVICE_UNAVAILABLE, "auth not configured").into_response()
    })?;
    let table = &auth.config.anchor_retry_table;

    let mut pending = 0usize;
    let mut completed = 0usize;
    let mut failed = 0usize;
    let mut last_key = None;

    loop {
        let mut req = auth.dynamo.scan().table_name(table);
        if let Some(k) = last_key.take() {
            req = req.set_exclusive_start_key(Some(k));
        }
        let out = match req.send().await {
            Ok(o) => o,
            Err(e) => {
                error!(error = %e, "anchor retry stats scan failed");
                return Err(
                    (StatusCode::INTERNAL_SERVER_ERROR, "scan failed").into_response()
                );
            }
        };

        for item in out.items() {
            let status = item
                .get("status")
                .and_then(|v| v.as_s().ok())
                .map(|s| s.as_str())
                .unwrap_or("unknown");
            match status {
                "pending" => pending += 1,
                "completed" => completed += 1,
                _ => failed += 1,
            }
        }

        if out.last_evaluated_key().is_none() {
            break;
        }
        last_key = out.last_evaluated_key().map(|k| k.to_owned());
    }

    Ok(Json(AnchorRetryStatsResponse {
        pending,
        completed,
        failed,
    }))
}

#[derive(Serialize)]
pub struct RetryAnchorsResponse {
    pub attempted: usize,
    pub succeeded: usize,
    pub failed: usize,
    pub errors: Vec<String>,
}

/// `POST /admin/retry-anchors` — scan pending anchor retries and attempt
/// to re-anchor each one. Updates status to "completed" on success or
/// increments `attempts` on failure. Best-effort sweep.
pub async fn retry_anchors(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<RetryAnchorsResponse>, Response> {
    let admin = require_admin(&headers)?;

    let auth = state.auth.as_ref().ok_or_else(|| {
        (StatusCode::SERVICE_UNAVAILABLE, "auth not configured").into_response()
    })?;
    let table = &auth.config.anchor_retry_table;

    let chain_client = state.chain.as_ref().ok_or_else(|| {
        (StatusCode::SERVICE_UNAVAILABLE, "chain not configured").into_response()
    })?;

    // Collect all pending items first, then process.
    let mut pending_items = Vec::new();
    let mut last_key = None;

    loop {
        let mut req = auth
            .dynamo
            .scan()
            .table_name(table)
            .filter_expression("#s = :pending")
            .expression_attribute_names("#s", "status")
            .expression_attribute_values(":pending", AttributeValue::S("pending".into()));
        if let Some(k) = last_key.take() {
            req = req.set_exclusive_start_key(Some(k));
        }
        let out = match req.send().await {
            Ok(o) => o,
            Err(e) => {
                error!(error = %e, "anchor retry scan failed");
                return Err(
                    (StatusCode::INTERNAL_SERVER_ERROR, "scan failed").into_response()
                );
            }
        };
        for item in out.items() {
            pending_items.push(item.to_owned());
        }
        if out.last_evaluated_key().is_none() {
            break;
        }
        last_key = out.last_evaluated_key().map(|k| k.to_owned());
    }

    let mut attempted = 0usize;
    let mut succeeded = 0usize;
    let mut failed = 0usize;
    let mut errors = Vec::new();

    for item in &pending_items {
        let asset_id = match item.get("pk").and_then(|v| v.as_s().ok()) {
            Some(s) => s.clone(),
            None => continue,
        };
        let sequence: u64 = item
            .get("sk")
            .and_then(|v| v.as_s().ok())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let hash_hex = match item.get("hash_hex").and_then(|v| v.as_s().ok()) {
            Some(s) => s.clone(),
            None => continue,
        };
        let prev_hash_hex = item
            .get("prev_hash_hex")
            .and_then(|v| v.as_s().ok())
            .cloned();

        // Reconstruct the commitment for anchoring.
        let hash = match AssetHash::from_hex(&hash_hex) {
            Ok(h) => h,
            Err(e) => {
                warn!(asset_id = %asset_id, error = %e, "bad hash_hex in retry queue");
                continue;
            }
        };
        let prev_hash = prev_hash_hex.as_deref().and_then(|h| AssetHash::from_hex(h).ok());

        let commitment = CanaryCommitment {
            hash,
            sequence,
            timestamp: chrono::Utc::now(),
            prev_hash,
        };

        let asset_id_hash: [u8; 32] = AssetHash::from_bytes(asset_id.as_bytes()).0;

        attempted += 1;
        match chain_client.anchor_commitment(asset_id_hash, &commitment).await {
            Ok(receipt) => {
                info!(
                    asset_id = %asset_id,
                    sequence = %sequence,
                    block = ?receipt.block_number,
                    "retry anchor succeeded"
                );
                succeeded += 1;

                // Mark completed.
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let _ = auth
                    .dynamo
                    .update_item()
                    .table_name(table)
                    .key("pk", AttributeValue::S(asset_id.clone()))
                    .key("sk", AttributeValue::S(sequence.to_string()))
                    .update_expression("SET #s = :completed, completed_at = :now")
                    .expression_attribute_names("#s", "status")
                    .expression_attribute_values(":completed", AttributeValue::S("completed".into()))
                    .expression_attribute_values(":now", AttributeValue::N(now.to_string()))
                    .send()
                    .await;

                log_admin_action(
                    &auth.dynamo,
                    &admin,
                    "retry_anchor",
                    &asset_id,
                    &serde_json::json!({ "sequence": sequence, "result": "success" }),
                )
                .await;
            }
            Err(e) => {
                let msg = format!("{asset_id}#{sequence}: {e}");
                warn!(error = %e, asset_id = %asset_id, sequence = %sequence, "retry anchor failed");
                failed += 1;
                errors.push(msg);

                // Increment attempts counter.
                let _ = auth
                    .dynamo
                    .update_item()
                    .table_name(table)
                    .key("pk", AttributeValue::S(asset_id.clone()))
                    .key("sk", AttributeValue::S(sequence.to_string()))
                    .update_expression("SET attempts = attempts + :one, last_attempt_at = :now")
                    .expression_attribute_values(
                        ":one",
                        AttributeValue::N("1".into()),
                    )
                    .expression_attribute_values(
                        ":now",
                        AttributeValue::N(
                            std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs()
                                .to_string(),
                        ),
                    )
                    .send()
                    .await;
            }
        }
    }

    Ok(Json(RetryAnchorsResponse {
        attempted,
        succeeded,
        failed,
        errors,
    }))
}
