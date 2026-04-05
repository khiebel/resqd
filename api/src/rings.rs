//! Family rings — shared vault groups with role-based access.
//!
//! A ring is a "virtual user" with its own X25519 keypair. Any member
//! who holds the ring's private key (wrapped so they can unwrap it)
//! can read every asset uploaded to the ring. Membership is an
//! individual ECDH-wrapped copy of the ring privkey — the server
//! never sees the plaintext, so ring membership is zero-knowledge.
//!
//! Roles (Owner / Adult / Child / Executor) are enforced server-side,
//! not cryptographically — all members hold the same ring privkey,
//! and the server checks the `role` field before allowing mutations.
//! Cryptographic role isolation (different keys for different roles)
//! is a Phase 5+ feature.
//!
//! # DynamoDB schema (`resqd-rings` table)
//!
//! Single-table design:
//!
//! | pk                  | sk                  | Data                                     |
//! |---------------------|---------------------|------------------------------------------|
//! | `RING#{ring_id}`    | `META`              | name, ring_pubkey, owner, created_at     |
//! | `RING#{ring_id}`    | `MEMBER#{user_id}`  | email, role, wrapped_ring_privkey, etc.  |
//!
//! GSI `user_id-index` with pk = `user_id` → "list my rings".

use crate::auth::{AuthState, AuthUser, AuthError, get_user_by_email};
use crate::state::AppState;
use aws_sdk_dynamodb::types::AttributeValue;
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use base64::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::info;
use uuid::Uuid;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ── Errors ──────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum RingError {
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("unauthorized")]
    Unauthorized,
    #[error("not found")]
    NotFound,
    #[error("forbidden: {0}")]
    Forbidden(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("dynamo: {0}")]
    Dynamo(String),
    #[error("auth: {0}")]
    Auth(#[from] AuthError),
    #[error("internal: {0}")]
    Internal(#[from] anyhow::Error),
}

impl<E: std::fmt::Debug + std::error::Error + 'static> From<aws_sdk_dynamodb::error::SdkError<E>>
    for RingError
{
    fn from(err: aws_sdk_dynamodb::error::SdkError<E>) -> Self {
        RingError::Dynamo(format!("{err:?}"))
    }
}

impl IntoResponse for RingError {
    fn into_response(self) -> Response {
        let (status, msg) = match &self {
            RingError::BadRequest(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            RingError::Unauthorized => (StatusCode::UNAUTHORIZED, self.to_string()),
            RingError::NotFound => (StatusCode::NOT_FOUND, self.to_string()),
            RingError::Forbidden(_) => (StatusCode::FORBIDDEN, self.to_string()),
            RingError::Conflict(_) => (StatusCode::CONFLICT, self.to_string()),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
        };
        (status, Json(serde_json::json!({ "error": msg }))).into_response()
    }
}

type RingResult<T> = Result<T, RingError>;

// ── DTOs ────────────────────────────────────────────────────────────

/// Valid ring member roles, ordered by privilege (Owner > Adult > Child > Executor).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Owner,
    Adult,
    Child,
    Executor,
}

impl Role {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "owner" => Some(Self::Owner),
            "adult" => Some(Self::Adult),
            "child" => Some(Self::Child),
            "executor" => Some(Self::Executor),
            _ => None,
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Adult => "adult",
            Self::Child => "child",
            Self::Executor => "executor",
        }
    }
    pub fn can_invite(&self) -> bool {
        matches!(self, Self::Owner | Self::Adult)
    }
    pub fn can_remove(&self) -> bool {
        matches!(self, Self::Owner)
    }
    pub fn can_write(&self) -> bool {
        matches!(self, Self::Owner | Self::Adult)
    }
    pub fn can_read(&self) -> bool {
        // Executor reads are gated by estate_unlocked_at, not here.
        // For now, all roles can read. Estate trigger enforcement will
        // layer on top in Phase 4.
        true
    }
}

#[derive(Deserialize)]
pub struct CreateRingRequest {
    pub name: String,
    /// Ring's X25519 public identity, base64. Stored in the META row.
    pub ring_pubkey_x25519_b64: String,
    /// Ring privkey wrapped for the caller via ECDH-to-self:
    /// `sender_wrap_key(my_priv, my_pub, ring_id)`. The caller
    /// generates the ring_id client-side via UUID so they can derive
    /// the wrap key before the POST.
    pub wrapped_ring_privkey_b64: String,
    /// Client-generated ring_id (UUID). The caller needs it ahead of
    /// time because the ECDH wrap key derivation binds the ring_id
    /// into the HKDF info field. The server validates it's a UUID.
    pub ring_id: String,
    /// Optional estate trigger config. When set, Executor-role members
    /// are locked out until the trigger fires.
    #[serde(default)]
    pub estate_trigger: Option<EstateTriggerConfig>,
}

/// Configuration for an estate trigger on a ring.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum EstateTriggerConfig {
    /// Unlock after no Owner-role member has been active for `days` days.
    /// "Active" means calling `/rings/{id}/me` (which the web UI does on
    /// every page load that shows ring data).
    #[serde(rename = "inactivity")]
    Inactivity { days: u64 },
    /// Unlock at a specific unix timestamp.
    #[serde(rename = "scheduled")]
    Scheduled { unlock_at: u64 },
}

#[derive(Serialize)]
pub struct CreateRingResponse {
    pub ring_id: String,
    pub name: String,
    pub created_at: u64,
}

#[derive(Serialize)]
pub struct RingSummary {
    pub ring_id: String,
    pub name: String,
    pub role: String,
    pub member_count: usize,
    pub created_at: u64,
}

#[derive(Serialize)]
pub struct RingDetail {
    pub ring_id: String,
    pub name: String,
    pub ring_pubkey_x25519_b64: String,
    pub owner_user_id: String,
    pub created_at: u64,
    pub members: Vec<MemberSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub estate_trigger: Option<EstateTriggerConfig>,
    /// Unix seconds of the last time an Owner-role member was active.
    /// Used by the inactivity trigger. Updated on every `/rings/{id}/me`
    /// call by an Owner.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_owner_activity_at: Option<u64>,
}

#[derive(Serialize)]
pub struct MemberSummary {
    pub user_id: String,
    pub email: String,
    pub role: String,
    pub invited_at: u64,
}

#[derive(Deserialize)]
pub struct InviteMemberRequest {
    pub invitee_email: String,
    pub role: String,
    /// Ring privkey wrapped for the invitee via
    /// `sender_wrap_key(inviter_priv, invitee_pub, ring_id)`.
    pub wrapped_ring_privkey_b64: String,
    /// Inviter's X25519 pubkey. Must match the caller's stored pubkey.
    pub inviter_pubkey_x25519_b64: String,
}

#[derive(Serialize)]
pub struct InviteMemberResponse {
    pub ring_id: String,
    pub invitee_user_id: String,
    pub invitee_email: String,
    pub role: String,
    pub invited_at: u64,
}

// ── Helpers ─────────────────────────────────────────────────────────

fn ring_pk(ring_id: &str) -> String {
    format!("RING#{ring_id}")
}

const META_SK: &str = "META";

fn member_sk(user_id: &str) -> String {
    format!("MEMBER#{user_id}")
}

fn take_s(item: &HashMap<String, AttributeValue>, key: &str) -> RingResult<String> {
    item.get(key)
        .and_then(|v| v.as_s().ok().cloned())
        .ok_or(RingError::Internal(anyhow::anyhow!("missing attr: {key}")))
}

fn take_s_opt(item: &HashMap<String, AttributeValue>, key: &str) -> Option<String> {
    item.get(key).and_then(|v| v.as_s().ok().cloned())
}

fn get_auth(state: &AppState) -> RingResult<&AuthState> {
    state.auth.as_ref().ok_or(RingError::Unauthorized)
}

/// Public re-export for use by `handlers.rs` ring-asset commit/fetch paths.
pub async fn get_caller_membership_pub(
    auth: &AuthState,
    ring_id: &str,
    user_id: &str,
) -> RingResult<Option<(Role, HashMap<String, AttributeValue>)>> {
    get_caller_membership(auth, ring_id, user_id).await
}

async fn get_caller_membership(
    auth: &AuthState,
    ring_id: &str,
    user_id: &str,
) -> RingResult<Option<(Role, HashMap<String, AttributeValue>)>> {
    let out = auth
        .dynamo
        .get_item()
        .table_name(&auth.config.rings_table)
        .key("pk", AttributeValue::S(ring_pk(ring_id)))
        .key("sk", AttributeValue::S(member_sk(user_id)))
        .send()
        .await?;
    let Some(item) = out.item else { return Ok(None) };
    let role_str = take_s(&item, "role")?;
    let role = Role::from_str(&role_str).ok_or(RingError::Internal(anyhow::anyhow!(
        "invalid role: {role_str}"
    )))?;
    Ok(Some((role, item)))
}

// ── Handlers ────────────────────────────────────────────────────────

/// `POST /rings` — create a new family ring. The caller becomes the
/// first member with role=Owner. The ring_id is client-generated (UUID)
/// because the ECDH wrap key derivation needs the ring_id in the HKDF
/// info before the POST can be made.
pub async fn create_ring(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<CreateRingRequest>,
) -> RingResult<Json<CreateRingResponse>> {
    let auth = get_auth(&state)?;

    // Validate ring_id looks like a UUID.
    if Uuid::parse_str(&req.ring_id).is_err() {
        return Err(RingError::BadRequest("ring_id must be a UUID".into()));
    }
    let name = req.name.trim().chars().take(128).collect::<String>();
    if name.is_empty() {
        return Err(RingError::BadRequest("name required".into()));
    }
    // Validate pubkey is 32 bytes.
    let pk_bytes = BASE64_STANDARD
        .decode(req.ring_pubkey_x25519_b64.trim())
        .map_err(|e| RingError::BadRequest(format!("ring_pubkey not base64: {e}")))?;
    if pk_bytes.len() != 32 {
        return Err(RingError::BadRequest(format!(
            "ring_pubkey must be 32 bytes, got {}",
            pk_bytes.len()
        )));
    }
    if req.wrapped_ring_privkey_b64.trim().is_empty() {
        return Err(RingError::BadRequest(
            "wrapped_ring_privkey_b64 required".into(),
        ));
    }

    // Verify caller has an X25519 identity (required for the ECDH-to-self
    // wrap of the ring privkey).
    let caller_row = get_user_by_email(auth, &user.email)
        .await
        .map_err(RingError::from)?
        .ok_or(RingError::Internal(anyhow::anyhow!("caller row missing")))?;
    if caller_row.pubkey_x25519_b64.is_none() {
        return Err(RingError::BadRequest(
            "mint an X25519 identity before creating a ring".into(),
        ));
    }

    let created_at = now_secs();

    // Write META row (conditional on not existing).
    let mut put = auth
        .dynamo
        .put_item()
        .table_name(&auth.config.rings_table)
        .item("pk", AttributeValue::S(ring_pk(&req.ring_id)))
        .item("sk", AttributeValue::S(META_SK.into()))
        .item("ring_id", AttributeValue::S(req.ring_id.clone()))
        .item("name", AttributeValue::S(name.clone()))
        .item(
            "ring_pubkey_x25519_b64",
            AttributeValue::S(req.ring_pubkey_x25519_b64.clone()),
        )
        .item(
            "owner_user_id",
            AttributeValue::S(user.user_id.clone()),
        )
        .item(
            "created_at",
            AttributeValue::N(created_at.to_string()),
        )
        .item(
            "last_owner_activity_at",
            AttributeValue::N(created_at.to_string()),
        )
        .condition_expression("attribute_not_exists(pk)");

    // Store estate trigger config as a JSON string attribute if provided.
    if let Some(trigger) = &req.estate_trigger {
        let trigger_json = serde_json::to_string(trigger)
            .map_err(|e| RingError::Internal(anyhow::anyhow!("serialize trigger: {e}")))?;
        put = put.item("estate_trigger", AttributeValue::S(trigger_json));
    }

    let meta_result = put.send().await;

    if let Err(e) = &meta_result {
        let msg = format!("{e:?}");
        if msg.contains("ConditionalCheckFailed") {
            return Err(RingError::Conflict("ring_id already exists".into()));
        }
        return Err(RingError::Dynamo(msg));
    }

    // Write the creator's membership row.
    auth.dynamo
        .put_item()
        .table_name(&auth.config.rings_table)
        .item("pk", AttributeValue::S(ring_pk(&req.ring_id)))
        .item(
            "sk",
            AttributeValue::S(member_sk(&user.user_id)),
        )
        .item("user_id", AttributeValue::S(user.user_id.clone()))
        .item("email", AttributeValue::S(user.email.clone()))
        .item("role", AttributeValue::S("owner".into()))
        .item(
            "wrapped_ring_privkey_b64",
            AttributeValue::S(req.wrapped_ring_privkey_b64.clone()),
        )
        .item(
            "inviter_pubkey_x25519_b64",
            AttributeValue::S(
                caller_row.pubkey_x25519_b64.unwrap_or_default(),
            ),
        )
        .item(
            "invited_at",
            AttributeValue::N(created_at.to_string()),
        )
        .item("ring_id", AttributeValue::S(req.ring_id.clone()))
        .send()
        .await?;

    info!(ring_id = %req.ring_id, owner = %user.user_id, "ring created");

    Ok(Json(CreateRingResponse {
        ring_id: req.ring_id,
        name,
        created_at,
    }))
}

/// `GET /rings` — list rings the caller is a member of. Uses the
/// `user_id-index` GSI which has `user_id` as pk.
pub async fn list_rings(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> RingResult<Json<Vec<RingSummary>>> {
    let auth = get_auth(&state)?;

    let out = auth
        .dynamo
        .query()
        .table_name(&auth.config.rings_table)
        .index_name("user_id-index")
        .key_condition_expression("user_id = :uid")
        .expression_attribute_values(":uid", AttributeValue::S(user.user_id.clone()))
        .send()
        .await?;

    let mut rings = Vec::new();
    for item in out.items() {
        let ring_id = match take_s_opt(item, "ring_id") {
            Some(id) => id,
            None => continue,
        };
        let role = take_s_opt(item, "role").unwrap_or_default();

        // Fetch the META row for name + created_at + member count.
        let meta_out = auth
            .dynamo
            .get_item()
            .table_name(&auth.config.rings_table)
            .key("pk", AttributeValue::S(ring_pk(&ring_id)))
            .key("sk", AttributeValue::S(META_SK.into()))
            .send()
            .await?;
        let Some(meta) = meta_out.item else { continue };

        // Count members by querying the ring's pk prefix.
        let members_out = auth
            .dynamo
            .query()
            .table_name(&auth.config.rings_table)
            .key_condition_expression("pk = :pk AND begins_with(sk, :prefix)")
            .expression_attribute_values(":pk", AttributeValue::S(ring_pk(&ring_id)))
            .expression_attribute_values(":prefix", AttributeValue::S("MEMBER#".into()))
            .select(aws_sdk_dynamodb::types::Select::Count)
            .send()
            .await?;

        rings.push(RingSummary {
            ring_id,
            name: take_s_opt(&meta, "name").unwrap_or_default(),
            role,
            member_count: members_out.count() as usize,
            created_at: take_s_opt(&meta, "created_at")
                .and_then(|s| s.parse().ok())
                .unwrap_or(0),
        });
    }

    Ok(Json(rings))
}

/// `GET /rings/{id}` — ring detail + full member list. Members only.
pub async fn get_ring(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(ring_id): Path<String>,
) -> RingResult<Json<RingDetail>> {
    let auth = get_auth(&state)?;

    // Verify caller is a member.
    let _membership = get_caller_membership(auth, &ring_id, &user.user_id)
        .await?
        .ok_or(RingError::NotFound)?;

    // Fetch all rows for this ring (META + all MEMBERs).
    let out = auth
        .dynamo
        .query()
        .table_name(&auth.config.rings_table)
        .key_condition_expression("pk = :pk")
        .expression_attribute_values(":pk", AttributeValue::S(ring_pk(&ring_id)))
        .send()
        .await?;

    let mut name = String::new();
    let mut ring_pubkey = String::new();
    let mut owner_user_id = String::new();
    let mut created_at = 0u64;
    let mut estate_trigger: Option<EstateTriggerConfig> = None;
    let mut last_owner_activity_at: Option<u64> = None;
    let mut members = Vec::new();

    for item in out.items() {
        let sk = take_s(item, "sk")?;
        if sk == META_SK {
            name = take_s_opt(item, "name").unwrap_or_default();
            ring_pubkey =
                take_s_opt(item, "ring_pubkey_x25519_b64").unwrap_or_default();
            owner_user_id = take_s_opt(item, "owner_user_id").unwrap_or_default();
            created_at = take_s_opt(item, "created_at")
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            estate_trigger = take_s_opt(item, "estate_trigger")
                .and_then(|s| serde_json::from_str(&s).ok());
            last_owner_activity_at = take_s_opt(item, "last_owner_activity_at")
                .and_then(|s| s.parse().ok());
        } else if let Some(uid) = sk.strip_prefix("MEMBER#") {
            members.push(MemberSummary {
                user_id: uid.to_string(),
                email: take_s_opt(item, "email").unwrap_or_default(),
                role: take_s_opt(item, "role").unwrap_or_default(),
                invited_at: take_s_opt(item, "invited_at")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0),
            });
        }
    }

    Ok(Json(RingDetail {
        ring_id,
        name,
        ring_pubkey_x25519_b64: ring_pubkey,
        owner_user_id,
        created_at,
        members,
        estate_trigger,
        last_owner_activity_at,
    }))
}

/// `POST /rings/{id}/members` — invite a user to the ring. The caller
/// must be a member with Owner or Adult role. The client pre-computes
/// the ECDH-wrapped ring privkey for the invitee and includes it in the
/// request — the server verifies the caller's pubkey matches their
/// stored identity but never sees the ring privkey in plaintext.
pub async fn invite_member(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(ring_id): Path<String>,
    Json(req): Json<InviteMemberRequest>,
) -> RingResult<Json<InviteMemberResponse>> {
    let auth = get_auth(&state)?;

    // Check caller is a member with invite perms.
    let (caller_role, _) = get_caller_membership(auth, &ring_id, &user.user_id)
        .await?
        .ok_or(RingError::NotFound)?;
    if !caller_role.can_invite() {
        return Err(RingError::Forbidden(format!(
            "role '{}' cannot invite members",
            caller_role.as_str()
        )));
    }

    // Validate role.
    let role = Role::from_str(&req.role).ok_or(RingError::BadRequest(format!(
        "invalid role '{}' — must be owner, adult, child, or executor",
        req.role
    )))?;

    // Only Owners can create other Owners.
    if role == Role::Owner && caller_role != Role::Owner {
        return Err(RingError::Forbidden(
            "only owners can create other owners".into(),
        ));
    }

    // Verify inviter pubkey matches stored identity.
    let caller_row = get_user_by_email(auth, &user.email)
        .await
        .map_err(RingError::from)?
        .ok_or(RingError::Internal(anyhow::anyhow!("caller missing")))?;
    let stored_pk = caller_row
        .pubkey_x25519_b64
        .as_deref()
        .ok_or(RingError::BadRequest("caller has no identity".into()))?;
    if stored_pk != req.inviter_pubkey_x25519_b64 {
        return Err(RingError::BadRequest(
            "inviter_pubkey does not match caller's stored identity".into(),
        ));
    }

    // Resolve invitee.
    let email = req.invitee_email.trim().to_ascii_lowercase();
    if email.is_empty() || !email.contains('@') {
        return Err(RingError::BadRequest("valid invitee_email required".into()));
    }
    if email == user.email {
        return Err(RingError::BadRequest("cannot invite yourself".into()));
    }
    let invitee = get_user_by_email(auth, &email)
        .await
        .map_err(RingError::from)?
        .ok_or(RingError::NotFound)?;
    if invitee.pubkey_x25519_b64.is_none() {
        return Err(RingError::BadRequest(
            "invitee has no X25519 identity yet — they must log in first".into(),
        ));
    }

    // Check not already a member.
    if get_caller_membership(auth, &ring_id, &invitee.user_id)
        .await?
        .is_some()
    {
        return Err(RingError::Conflict(
            "user is already a member of this ring".into(),
        ));
    }

    let invited_at = now_secs();

    auth.dynamo
        .put_item()
        .table_name(&auth.config.rings_table)
        .item("pk", AttributeValue::S(ring_pk(&ring_id)))
        .item(
            "sk",
            AttributeValue::S(member_sk(&invitee.user_id)),
        )
        .item("user_id", AttributeValue::S(invitee.user_id.clone()))
        .item("email", AttributeValue::S(invitee.email.clone()))
        .item("role", AttributeValue::S(role.as_str().into()))
        .item(
            "wrapped_ring_privkey_b64",
            AttributeValue::S(req.wrapped_ring_privkey_b64.clone()),
        )
        .item(
            "inviter_pubkey_x25519_b64",
            AttributeValue::S(req.inviter_pubkey_x25519_b64.clone()),
        )
        .item(
            "invited_at",
            AttributeValue::N(invited_at.to_string()),
        )
        .item("ring_id", AttributeValue::S(ring_id.clone()))
        .send()
        .await?;

    info!(
        ring_id = %ring_id,
        inviter = %user.user_id,
        invitee = %invitee.user_id,
        role = %role.as_str(),
        "ring member invited"
    );

    Ok(Json(InviteMemberResponse {
        ring_id,
        invitee_user_id: invitee.user_id,
        invitee_email: invitee.email,
        role: role.as_str().to_string(),
        invited_at,
    }))
}

/// `DELETE /rings/{id}/members/{email}` — remove a member. Owner only.
/// Cannot remove the last owner (that would leave the ring orphaned).
pub async fn remove_member(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path((ring_id, target_email)): Path<(String, String)>,
) -> RingResult<Json<serde_json::Value>> {
    let auth = get_auth(&state)?;

    let (caller_role, _) = get_caller_membership(auth, &ring_id, &user.user_id)
        .await?
        .ok_or(RingError::NotFound)?;
    if !caller_role.can_remove() {
        return Err(RingError::Forbidden(format!(
            "role '{}' cannot remove members",
            caller_role.as_str()
        )));
    }

    let target_email = target_email.trim().to_ascii_lowercase();
    let target = get_user_by_email(auth, &target_email)
        .await
        .map_err(RingError::from)?
        .ok_or(RingError::NotFound)?;

    // Don't allow removing self if sole owner.
    if target.user_id == user.user_id {
        // Count other owners.
        let members_out = auth
            .dynamo
            .query()
            .table_name(&auth.config.rings_table)
            .key_condition_expression("pk = :pk AND begins_with(sk, :prefix)")
            .expression_attribute_values(":pk", AttributeValue::S(ring_pk(&ring_id)))
            .expression_attribute_values(":prefix", AttributeValue::S("MEMBER#".into()))
            .send()
            .await?;
        let other_owners = members_out
            .items()
            .iter()
            .filter(|i| {
                take_s_opt(i, "role").as_deref() == Some("owner")
                    && take_s_opt(i, "user_id").as_deref() != Some(&user.user_id)
            })
            .count();
        if other_owners == 0 {
            return Err(RingError::Forbidden(
                "cannot remove yourself as the sole owner — transfer ownership first".into(),
            ));
        }
    }

    auth.dynamo
        .delete_item()
        .table_name(&auth.config.rings_table)
        .key("pk", AttributeValue::S(ring_pk(&ring_id)))
        .key(
            "sk",
            AttributeValue::S(member_sk(&target.user_id)),
        )
        .send()
        .await?;

    info!(
        ring_id = %ring_id,
        remover = %user.user_id,
        removed = %target.user_id,
        "ring member removed"
    );

    Ok(Json(serde_json::json!({
        "ring_id": ring_id,
        "removed_email": target_email,
        "removed": true,
    })))
}

/// `PUT /rings/{id}/trigger` — set or update the estate trigger config.
/// Owner only.
pub async fn set_trigger(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(ring_id): Path<String>,
    Json(req): Json<SetTriggerRequest>,
) -> RingResult<Json<serde_json::Value>> {
    let auth = get_auth(&state)?;

    let (caller_role, _) = get_caller_membership(auth, &ring_id, &user.user_id)
        .await?
        .ok_or(RingError::NotFound)?;
    if caller_role != Role::Owner {
        return Err(RingError::Forbidden(
            "only owners can configure estate triggers".into(),
        ));
    }

    // Validate the trigger config.
    match &req.estate_trigger {
        Some(EstateTriggerConfig::Inactivity { days }) => {
            if *days == 0 || *days > 3650 {
                return Err(RingError::BadRequest(
                    "inactivity days must be 1–3650".into(),
                ));
            }
        }
        Some(EstateTriggerConfig::Scheduled { unlock_at }) => {
            if *unlock_at <= now_secs() {
                return Err(RingError::BadRequest(
                    "scheduled unlock_at must be in the future".into(),
                ));
            }
        }
        None => {} // clearing the trigger
    }

    if let Some(trigger) = &req.estate_trigger {
        let trigger_json = serde_json::to_string(trigger)
            .map_err(|e| RingError::Internal(anyhow::anyhow!("serialize: {e}")))?;
        auth.dynamo
            .update_item()
            .table_name(&auth.config.rings_table)
            .key("pk", AttributeValue::S(ring_pk(&ring_id)))
            .key("sk", AttributeValue::S(META_SK.into()))
            .update_expression("SET estate_trigger = :t")
            .expression_attribute_values(":t", AttributeValue::S(trigger_json))
            .send()
            .await?;
    } else {
        auth.dynamo
            .update_item()
            .table_name(&auth.config.rings_table)
            .key("pk", AttributeValue::S(ring_pk(&ring_id)))
            .key("sk", AttributeValue::S(META_SK.into()))
            .update_expression("REMOVE estate_trigger")
            .send()
            .await?;
    }

    info!(ring_id = %ring_id, "estate trigger updated");
    Ok(Json(serde_json::json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct SetTriggerRequest {
    pub estate_trigger: Option<EstateTriggerConfig>,
}

/// `GET /rings/{id}/me` — return the caller's own membership record
/// including their `wrapped_ring_privkey_b64` so the browser can
/// unwrap the ring privkey and use it for ring-asset crypto. This
/// is the ring equivalent of `/auth/me` returning `wrapped_privkey_x25519_b64`.
pub async fn my_membership(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(ring_id): Path<String>,
) -> RingResult<Json<serde_json::Value>> {
    let auth = get_auth(&state)?;
    let (role, item) = get_caller_membership(auth, &ring_id, &user.user_id)
        .await?
        .ok_or(RingError::NotFound)?;

    // Fetch ring META for the pubkey + estate trigger config.
    let meta_out = auth
        .dynamo
        .get_item()
        .table_name(&auth.config.rings_table)
        .key("pk", AttributeValue::S(ring_pk(&ring_id)))
        .key("sk", AttributeValue::S(META_SK.into()))
        .send()
        .await?;
    let meta = meta_out.item.ok_or(RingError::NotFound)?;

    // ── Owner heartbeat ──
    // Every time an Owner visits this endpoint (which the web UI hits
    // on page load), bump `last_owner_activity_at` on the ring META
    // row. This is the inactivity trigger's clock source.
    if role == Role::Owner {
        let _ = auth
            .dynamo
            .update_item()
            .table_name(&auth.config.rings_table)
            .key("pk", AttributeValue::S(ring_pk(&ring_id)))
            .key("sk", AttributeValue::S(META_SK.into()))
            .update_expression("SET last_owner_activity_at = :t")
            .expression_attribute_values(
                ":t",
                AttributeValue::N(now_secs().to_string()),
            )
            .send()
            .await;
    }

    // ── Executor estate gate ──
    // Executors only receive their wrapped ring privkey after the
    // estate trigger has fired. We check the condition lazily here
    // and set `estate_unlocked_at` if it's met. If not, we return
    // the response WITHOUT the wrapped key and with a clear message.
    if role == Role::Executor {
        let already_unlocked = take_s_opt(&item, "estate_unlocked_at")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0)
            > 0;

        if !already_unlocked {
            let trigger: Option<EstateTriggerConfig> = take_s_opt(&meta, "estate_trigger")
                .and_then(|s| serde_json::from_str(&s).ok());

            let should_unlock = match &trigger {
                Some(EstateTriggerConfig::Inactivity { days }) => {
                    let last_activity = take_s_opt(&meta, "last_owner_activity_at")
                        .and_then(|s| s.parse::<u64>().ok())
                        .unwrap_or(0);
                    let threshold = *days * 86400;
                    last_activity > 0 && now_secs().saturating_sub(last_activity) >= threshold
                }
                Some(EstateTriggerConfig::Scheduled { unlock_at }) => {
                    now_secs() >= *unlock_at
                }
                None => false,
            };

            if should_unlock {
                // Fire the trigger: set estate_unlocked_at on the
                // Executor's membership row.
                let _ = auth
                    .dynamo
                    .update_item()
                    .table_name(&auth.config.rings_table)
                    .key("pk", AttributeValue::S(ring_pk(&ring_id)))
                    .key(
                        "sk",
                        AttributeValue::S(member_sk(&user.user_id)),
                    )
                    .update_expression("SET estate_unlocked_at = :t")
                    .expression_attribute_values(
                        ":t",
                        AttributeValue::N(now_secs().to_string()),
                    )
                    .send()
                    .await;
                info!(ring_id = %ring_id, executor = %user.user_id, "estate trigger fired — executor unlocked");
            } else {
                // Not yet unlocked — return a response without the
                // wrapped key so the Executor knows they're locked
                // out and why.
                let trigger_desc = match &trigger {
                    Some(EstateTriggerConfig::Inactivity { days }) => {
                        format!("inactivity trigger ({days} days)")
                    }
                    Some(EstateTriggerConfig::Scheduled { unlock_at }) => {
                        format!("scheduled trigger (unix {unlock_at})")
                    }
                    None => "no trigger configured".into(),
                };
                return Ok(Json(serde_json::json!({
                    "ring_id": ring_id,
                    "role": "executor",
                    "estate_locked": true,
                    "estate_trigger": trigger_desc,
                    "ring_pubkey_x25519_b64": take_s_opt(&meta, "ring_pubkey_x25519_b64"),
                    // No wrapped_ring_privkey_b64 — locked.
                })));
            }
        }
    }

    Ok(Json(serde_json::json!({
        "ring_id": ring_id,
        "role": role.as_str(),
        "ring_pubkey_x25519_b64": take_s_opt(&meta, "ring_pubkey_x25519_b64"),
        "wrapped_ring_privkey_b64": take_s_opt(&item, "wrapped_ring_privkey_b64"),
        "inviter_pubkey_x25519_b64": take_s_opt(&item, "inviter_pubkey_x25519_b64"),
    })))
}
