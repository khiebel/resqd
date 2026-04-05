//! Passkey authentication with WebAuthn + DynamoDB.
//!
//! # Design
//!
//! - **Passkeys only.** No passwords, no hex keys. Users sign up by giving
//!   an email (for login lookup + support contact) and performing one
//!   WebAuthn registration ceremony. Subsequent logins are just email +
//!   platform biometric.
//! - **Key derivation via the PRF extension.** The server is PRF-agnostic:
//!   it runs the standard webauthn-rs ceremony and stores only the Passkey
//!   public key. The browser injects the PRF extension on both register
//!   and auth, reads the PRF output locally, and derives the vault master
//!   key. That key never leaves the browser. The PRF salt is a fixed
//!   per-app constant baked into the frontend (`resqd-vault-prf-v1`), so
//!   PRF output uniqueness comes from the credential itself — which is
//!   exactly what PRF guarantees.
//! - **Stateless sessions** via HS256 JWT stored in a cookie. The cookie
//!   is `HttpOnly; Secure; SameSite=<configurable>; Path=/`.
//! - **DynamoDB** holds two small tables: `resqd-users` (the passkey
//!   credential + metadata, keyed by email) and `resqd-auth-challenges`
//!   (short-lived webauthn state, TTL 5 min via the `expires_at` attr).

use aws_sdk_dynamodb::Client as DynamoClient;
use aws_sdk_dynamodb::types::AttributeValue;
use axum::{
    Json,
    extract::{FromRequestParts, OptionalFromRequestParts, Query, State},
    http::{StatusCode, header, request::Parts},
    response::{IntoResponse, Response},
};
use base64::prelude::*;
use jsonwebtoken::{DecodingKey, EncodingKey, Header as JwtHeader, Validation, decode, encode};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{error, info, warn};
use url::Url;
use uuid::Uuid;
use webauthn_rs::prelude::*;

use crate::state::AppState;

// ────────────────────────────────────────────────────────────────────
//                            Config
// ────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug)]
pub enum CookieSameSite {
    Strict,
    Lax,
    None,
}

impl CookieSameSite {
    fn as_str(self) -> &'static str {
        match self {
            Self::Strict => "Strict",
            Self::Lax => "Lax",
            Self::None => "None",
        }
    }
}

#[derive(Clone, Debug)]
pub struct AuthConfig {
    pub rp_id: String,
    pub rp_name: String,
    pub origin: Url,
    pub jwt_secret: Vec<u8>,
    pub users_table: String,
    pub challenges_table: String,
    pub tokens_table: String,
    pub rings_table: String,
    pub session_ttl_secs: u64,
    pub cookie_domain: Option<String>,
    pub cookie_secure: bool,
    pub cookie_same_site: CookieSameSite,
}

impl AuthConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        use anyhow::Context;

        let rp_id = std::env::var("RESQD_WEBAUTHN_RP_ID").unwrap_or_else(|_| "localhost".into());
        let rp_name = std::env::var("RESQD_WEBAUTHN_RP_NAME").unwrap_or_else(|_| "RESQD".into());
        let origin_str = std::env::var("RESQD_WEBAUTHN_ORIGIN")
            .unwrap_or_else(|_| "http://localhost:3000".into());
        let origin = Url::parse(&origin_str).context("RESQD_WEBAUTHN_ORIGIN must be a URL")?;

        let jwt_secret = match std::env::var("RESQD_JWT_SECRET") {
            Ok(s) => BASE64_STANDARD
                .decode(s.trim())
                .context("RESQD_JWT_SECRET must be standard base64")?,
            Err(_) => {
                // Ephemeral secret — sessions don't survive restart. Fine for
                // local dev, broken in prod, so we warn loudly.
                let mut bytes = vec![0u8; 32];
                rand::thread_rng().fill_bytes(&mut bytes);
                warn!("RESQD_JWT_SECRET not set — using ephemeral random secret");
                bytes
            }
        };
        if jwt_secret.len() < 32 {
            anyhow::bail!("RESQD_JWT_SECRET must decode to at least 32 bytes");
        }

        let users_table =
            std::env::var("RESQD_USERS_TABLE").unwrap_or_else(|_| "resqd-users".into());
        let challenges_table = std::env::var("RESQD_CHALLENGES_TABLE")
            .unwrap_or_else(|_| "resqd-auth-challenges".into());
        let tokens_table =
            std::env::var("RESQD_TOKENS_TABLE").unwrap_or_else(|_| "resqd-api-tokens".into());
        let rings_table =
            std::env::var("RESQD_RINGS_TABLE").unwrap_or_else(|_| "resqd-rings".into());

        let cookie_domain = std::env::var("RESQD_COOKIE_DOMAIN").ok();
        let cookie_secure = std::env::var("RESQD_COOKIE_SECURE")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(true);
        let cookie_same_site = match std::env::var("RESQD_COOKIE_SAMESITE")
            .unwrap_or_else(|_| "None".into())
            .to_ascii_lowercase()
            .as_str()
        {
            "strict" => CookieSameSite::Strict,
            "lax" => CookieSameSite::Lax,
            _ => CookieSameSite::None,
        };

        Ok(Self {
            rp_id,
            rp_name,
            origin,
            jwt_secret,
            users_table,
            challenges_table,
            tokens_table,
            rings_table,
            session_ttl_secs: 7 * 24 * 3600,
            cookie_domain,
            cookie_secure,
            cookie_same_site,
        })
    }
}

// ────────────────────────────────────────────────────────────────────
//                             State
// ────────────────────────────────────────────────────────────────────

pub struct AuthState {
    pub config: AuthConfig,
    pub webauthn: Arc<Webauthn>,
    pub dynamo: DynamoClient,
}

impl AuthState {
    pub async fn from_config(config: AuthConfig) -> anyhow::Result<Self> {
        // Primary origin is `config.origin`. Additional origins can be
        // passed through `RESQD_WEBAUTHN_ADDITIONAL_ORIGINS` (comma-
        // separated) — used during the app.resqd.ai → resqd.ai
        // consolidation so passkeys registered against either subdomain
        // verify against the same RP id on either host.
        let mut builder = WebauthnBuilder::new(&config.rp_id, &config.origin)?
            .rp_name(&config.rp_name);
        if let Ok(extras) = std::env::var("RESQD_WEBAUTHN_ADDITIONAL_ORIGINS") {
            for o in extras.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                match Url::parse(o) {
                    Ok(url) => {
                        builder = builder.append_allowed_origin(&url);
                    }
                    Err(e) => tracing::warn!(origin = %o, error = %e, "invalid additional origin"),
                }
            }
        }
        let webauthn = Arc::new(builder.build()?);
        let aws_conf = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let dynamo = DynamoClient::new(&aws_conf);
        Ok(Self {
            config,
            webauthn,
            dynamo,
        })
    }
}

// ────────────────────────────────────────────────────────────────────
//                          DynamoDB rows
// ────────────────────────────────────────────────────────────────────

/// Row in `resqd-users`. Primary key is `email` (lowercased, trimmed) —
/// this lets us look up a user on login without maintaining a second GSI
/// just for email. The opaque `user_id` (UUID) is what goes in the JWT
/// `sub` and ends up on assets as the owner id, so the email can be
/// changed later (we'd copy-delete the row) without invalidating any
/// downstream references.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct UserRow {
    pub email: String,
    pub user_id: String,
    /// base64url of the WebAuthn credential id. Also the partition key of
    /// the `credential_id-index` GSI for reverse lookups.
    pub credential_id: String,
    /// Full `Passkey` JSON from webauthn-rs (requires
    /// `danger-allow-state-serialisation` feature).
    pub passkey_json: String,
    pub display_name: String,
    pub created_at: u64,
    /// Sum of `original_len` across every asset the user has committed
    /// and not yet deleted. Used as the basis for the per-user storage
    /// cap — see `QUOTA_BYTES`. `None` in the struct here just means
    /// "not yet loaded"; the row itself defaults to 0 at registration.
    #[serde(default)]
    pub storage_used_bytes: Option<u64>,
    /// Long-term X25519 public identity (base64). Minted client-side on
    /// first login post-identity-rollout and PUT to
    /// `/auth/me/identity`. Used as the recipient pubkey when another
    /// user shares an asset with this user. `None` for rows that
    /// haven't upgraded yet — they can still read their own vault and
    /// will be prompted to establish an identity next time they log in
    /// with PRF support. Immutable once set.
    #[serde(default)]
    pub pubkey_x25519_b64: Option<String>,
    /// X25519 private key sealed under the user's PRF-derived master
    /// key via the standard XChaCha20-Poly1305 envelope. Stored on the
    /// server but unreadable without the master key, so the server
    /// still holds no useful key material. Fetched by the browser on
    /// each login, unwrapped with the master key, and cached in
    /// session storage next to `resqd_master_key`. Required on the
    /// sharing read path so the recipient can ECDH against the
    /// sender's pubkey without a fresh passkey prompt.
    #[serde(default)]
    pub wrapped_privkey_x25519_b64: Option<String>,
}

/// Row in `resqd-auth-challenges`. Stores the serialized webauthn state
/// between begin and finish. TTL is enforced by DynamoDB via the
/// `expires_at` attribute (unix seconds).
#[derive(Serialize, Deserialize, Clone, Debug)]
struct ChallengeRow {
    challenge_id: String,
    kind: String, // "registration" | "authentication"
    /// Serialized `PasskeyRegistration` or `PasskeyAuthentication`.
    state_json: String,
    /// Pre-filled during register_begin (we know the email they're claiming)
    /// and during login_begin.
    email: Option<String>,
    expires_at: u64,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn normalize_email(input: &str) -> String {
    input.trim().to_ascii_lowercase()
}

// ────────────────────────────────────────────────────────────────────
//                          Errors
// ────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("unauthorized")]
    Unauthorized,
    #[error("not found")]
    NotFound,
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("webauthn: {0}")]
    Webauthn(#[from] WebauthnError),
    #[error("dynamo: {0}")]
    Dynamo(String),
    #[error("internal: {0}")]
    Internal(#[from] anyhow::Error),
}

impl<E: std::fmt::Debug + std::error::Error + 'static> From<aws_sdk_dynamodb::error::SdkError<E>>
    for AuthError
{
    fn from(err: aws_sdk_dynamodb::error::SdkError<E>) -> Self {
        // Surface the full error chain — `Display` on SdkError just says
        // "service error" and drops the useful detail on the floor. Walk
        // `source()` manually and concatenate each layer.
        use std::error::Error as _;
        let mut msg = format!("{err}");
        let mut cursor: Option<&(dyn std::error::Error + 'static)> = err.source();
        while let Some(s) = cursor {
            msg.push_str(" | ");
            msg.push_str(&format!("{s}"));
            cursor = s.source();
        }
        AuthError::Dynamo(msg)
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, msg) = match &self {
            AuthError::BadRequest(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            AuthError::Unauthorized => (StatusCode::UNAUTHORIZED, self.to_string()),
            AuthError::NotFound => (StatusCode::NOT_FOUND, self.to_string()),
            AuthError::Conflict(_) => (StatusCode::CONFLICT, self.to_string()),
            AuthError::Webauthn(e) => {
                info!(error = ?e, "webauthn error");
                (StatusCode::BAD_REQUEST, format!("webauthn: {e}"))
            }
            _ => {
                error!(error = %self, "auth handler error");
                (StatusCode::INTERNAL_SERVER_ERROR, self.to_string())
            }
        };
        (status, Json(serde_json::json!({ "error": msg }))).into_response()
    }
}

type AuthResult<T> = Result<T, AuthError>;

// ────────────────────────────────────────────────────────────────────
//                          DTOs
// ────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct RegisterBeginRequest {
    pub email: String,
    #[serde(default)]
    pub display_name: Option<String>,
}

#[derive(Serialize)]
pub struct RegisterBeginResponse {
    pub challenge_id: String,
    /// The `CreationChallengeResponse` from webauthn-rs, passed through
    /// as opaque JSON. The browser merges our PRF extension into this
    /// object's `publicKey.extensions` before calling `navigator.credentials.create()`.
    pub creation_options: serde_json::Value,
}

#[derive(Deserialize)]
pub struct RegisterFinishRequest {
    pub challenge_id: String,
    pub credential: RegisterPublicKeyCredential,
}

#[derive(Deserialize)]
pub struct LoginBeginRequest {
    pub email: String,
}

#[derive(Serialize)]
pub struct LoginBeginResponse {
    pub challenge_id: String,
    pub request_options: serde_json::Value,
}

#[derive(Deserialize)]
pub struct LoginFinishRequest {
    pub challenge_id: String,
    pub credential: PublicKeyCredential,
}

#[derive(Serialize)]
pub struct SessionResponse {
    pub user_id: String,
    pub email: String,
    pub display_name: String,
}

#[derive(Serialize)]
pub struct MeResponse {
    pub user_id: String,
    pub email: String,
    pub display_name: String,
    /// Bytes currently consumed by this user's vault.
    pub storage_used_bytes: u64,
    /// Hard cap enforced on commit. See `QUOTA_BYTES`.
    pub storage_quota_bytes: u64,
    /// Long-term X25519 public identity, base64. Empty string if the
    /// user hasn't established one yet (pre-identity-rollout rows) —
    /// the browser uses this as a signal to run the one-time identity
    /// mint flow on next PRF-capable login.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pubkey_x25519_b64: Option<String>,
    /// Master-key-sealed X25519 private identity, base64. Only this
    /// user ever receives their own wrapped privkey (it's inside their
    /// own auth'd `/auth/me` response), and the server cannot unwrap
    /// it without the PRF-derived master key it has never seen.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wrapped_privkey_x25519_b64: Option<String>,
}

/// Request body for `PUT /auth/me/identity`. Browser-generated X25519
/// keypair: public half in the clear, private half already sealed under
/// the master key client-side. The server writes both into the user row
/// with a conditional update so the first successful caller wins and
/// subsequent calls are rejected — identities are immutable for the
/// life of the account (rotating them would silently invalidate every
/// share that pointed at the old pubkey).
#[derive(Deserialize)]
pub struct SetIdentityRequest {
    pub pubkey_x25519_b64: String,
    pub wrapped_privkey_x25519_b64: String,
}

/// Response to `GET /users/lookup?email=X`. Exposes ONLY the public
/// half of another user's long-term identity — enough for the caller
/// to ECDH-derive a share wrap key, nothing more. Requires a valid
/// session so random unauthenticated clients can't harvest pubkeys.
#[derive(Serialize)]
pub struct UserLookupResponse {
    pub user_id: String,
    pub email: String,
    pub display_name: String,
    pub pubkey_x25519_b64: String,
}

// ────────────────────────────────────────────────────────────────────
//                          JWT / cookie
// ────────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct SessionClaims {
    sub: String, // user_id
    email: String,
    name: String,
    exp: u64,
    iat: u64,
}

const SESSION_COOKIE: &str = "resqd_session";

fn issue_session_cookie(cfg: &AuthConfig, user: &UserRow) -> AuthResult<String> {
    let iat = now_secs();
    let exp = iat + cfg.session_ttl_secs;
    let claims = SessionClaims {
        sub: user.user_id.clone(),
        email: user.email.clone(),
        name: user.display_name.clone(),
        iat,
        exp,
    };
    let token = encode(
        &JwtHeader::default(),
        &claims,
        &EncodingKey::from_secret(&cfg.jwt_secret),
    )
    .map_err(|e| AuthError::Internal(anyhow::anyhow!("jwt encode: {e}")))?;

    let mut parts = vec![
        format!("{SESSION_COOKIE}={token}"),
        "HttpOnly".into(),
        "Path=/".into(),
        format!("Max-Age={}", cfg.session_ttl_secs),
        format!("SameSite={}", cfg.cookie_same_site.as_str()),
    ];
    if cfg.cookie_secure {
        parts.push("Secure".into());
    }
    if let Some(d) = &cfg.cookie_domain {
        parts.push(format!("Domain={d}"));
    }
    Ok(parts.join("; "))
}

fn clear_session_cookie(cfg: &AuthConfig) -> String {
    let mut parts = vec![
        format!("{SESSION_COOKIE}=deleted"),
        "HttpOnly".into(),
        "Path=/".into(),
        "Max-Age=0".into(),
        format!("SameSite={}", cfg.cookie_same_site.as_str()),
    ];
    if cfg.cookie_secure {
        parts.push("Secure".into());
    }
    if let Some(d) = &cfg.cookie_domain {
        parts.push(format!("Domain={d}"));
    }
    parts.join("; ")
}

fn verify_session(cfg: &AuthConfig, token: &str) -> AuthResult<SessionClaims> {
    let data = decode::<SessionClaims>(
        token,
        &DecodingKey::from_secret(&cfg.jwt_secret),
        &Validation::default(),
    )
    .map_err(|_| AuthError::Unauthorized)?;
    Ok(data.claims)
}

fn extract_cookie<'a>(cookie_header: &'a str, name: &str) -> Option<&'a str> {
    for part in cookie_header.split(';') {
        let part = part.trim();
        if let Some(rest) = part.strip_prefix(&format!("{name}=")) {
            return Some(rest);
        }
    }
    None
}

/// Axum extractor: parses the session cookie and yields the authed user.
/// Handlers that need auth take `AuthUser` as an extractor. Unauth'd
/// requests short-circuit with 401.
#[derive(Clone, Debug)]
pub struct AuthUser {
    pub user_id: String,
    pub email: String,
    pub display_name: String,
}

impl FromRequestParts<Arc<AppState>> for AuthUser {
    type Rejection = AuthError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        // Cookie path — synchronous, no DB hit.
        if let Some(user) = extract_auth_user(parts, state)? {
            return Ok(user);
        }
        // Bearer-token path — async DynamoDB lookup.
        if let Some(token) = extract_bearer(parts) {
            let auth = state.auth.as_ref().ok_or(AuthError::Unauthorized)?;
            return verify_bearer_token(auth, &token).await;
        }
        Err(AuthError::Unauthorized)
    }
}

/// Optional variant so handlers can take `Option<AuthUser>` for endpoints
/// that accept both authed and anonymous callers (e.g. legacy vault
/// fetch paths). Axum 0.8 requires a separate `OptionalFromRequestParts`
/// impl — the blanket `FromRequestParts for Option<T>` from earlier
/// versions was removed to avoid ambiguity with rejections that can be
/// "genuinely missing" vs "malformed".
impl OptionalFromRequestParts<Arc<AppState>> for AuthUser {
    type Rejection = AuthError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Option<Self>, Self::Rejection> {
        if let Some(user) = extract_auth_user(parts, state)? {
            return Ok(Some(user));
        }
        if let Some(token) = extract_bearer(parts) {
            let Some(auth) = state.auth.as_ref() else {
                return Ok(None);
            };
            return match verify_bearer_token(auth, &token).await {
                Ok(u) => Ok(Some(u)),
                Err(AuthError::Unauthorized) => Ok(None),
                Err(e) => Err(e),
            };
        }
        Ok(None)
    }
}

fn extract_auth_user(parts: &Parts, state: &Arc<AppState>) -> AuthResult<Option<AuthUser>> {
    // Session cookie (human users via the browser SPA) takes precedence.
    // If there's no cookie, fall through to the `Authorization: Bearer`
    // path used by MCP clients / API consumers. We don't attempt DB
    // verification here — that's async and we can't await inside the
    // extractor's sync fast-path — so bearer verification happens in
    // the full `from_request_parts` path below.
    let Some(auth) = state.auth.as_ref() else {
        return Ok(None);
    };
    let cookie_header = parts
        .headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok());
    if let Some(ch) = cookie_header {
        if let Some(token) = extract_cookie(ch, SESSION_COOKIE) {
            let claims = verify_session(&auth.config, token)?;
            return Ok(Some(AuthUser {
                user_id: claims.sub,
                email: claims.email,
                display_name: claims.name,
            }));
        }
    }
    Ok(None)
}

/// Extract a bearer token from the `Authorization` header, if present.
fn extract_bearer(parts: &Parts) -> Option<String> {
    let raw = parts
        .headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())?;
    let rest = raw.strip_prefix("Bearer ").or_else(|| raw.strip_prefix("bearer "))?;
    Some(rest.trim().to_string())
}

/// Hash a raw API token for storage + lookup. We never store raw tokens —
/// only `sha256(token)` — so a dump of the `resqd-api-tokens` table can't
/// be replayed against the API. The hash is also the table partition key.
fn hash_token(raw: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(raw.as_bytes());
    format!("{:x}", h.finalize())
}

async fn verify_bearer_token(auth: &AuthState, raw: &str) -> AuthResult<AuthUser> {
    // Token format sanity check — this isn't security, it's a tiny
    // efficiency so we don't hit DynamoDB for obviously garbage input.
    if !raw.starts_with("rsqd_") || raw.len() < 16 {
        return Err(AuthError::Unauthorized);
    }
    let token_hash = hash_token(raw);
    let out = auth
        .dynamo
        .get_item()
        .table_name(&auth.config.tokens_table)
        .key("token_hash", AttributeValue::S(token_hash))
        .send()
        .await?;
    let item = out.item.ok_or(AuthError::Unauthorized)?;
    Ok(AuthUser {
        user_id: take_s(&item, "user_id")?,
        email: take_s(&item, "email").unwrap_or_default(),
        display_name: take_s(&item, "display_name").unwrap_or_default(),
    })
}

// ────────────────────────────────────────────────────────────────────
//                          DynamoDB helpers
// ────────────────────────────────────────────────────────────────────

async fn put_challenge(auth: &AuthState, row: &ChallengeRow) -> AuthResult<()> {
    let mut item: HashMap<String, AttributeValue> = HashMap::new();
    item.insert(
        "challenge_id".into(),
        AttributeValue::S(row.challenge_id.clone()),
    );
    item.insert("kind".into(), AttributeValue::S(row.kind.clone()));
    item.insert(
        "state_json".into(),
        AttributeValue::S(row.state_json.clone()),
    );
    if let Some(e) = &row.email {
        item.insert("email".into(), AttributeValue::S(e.clone()));
    }
    item.insert(
        "expires_at".into(),
        AttributeValue::N(row.expires_at.to_string()),
    );
    auth.dynamo
        .put_item()
        .table_name(&auth.config.challenges_table)
        .set_item(Some(item))
        .send()
        .await?;
    Ok(())
}

async fn take_challenge(auth: &AuthState, id: &str, kind: &str) -> AuthResult<ChallengeRow> {
    let out = auth
        .dynamo
        .get_item()
        .table_name(&auth.config.challenges_table)
        .key("challenge_id", AttributeValue::S(id.into()))
        .send()
        .await?;
    let item = out.item.ok_or(AuthError::BadRequest(
        "challenge not found or expired".into(),
    ))?;

    let row = ChallengeRow {
        challenge_id: take_s(&item, "challenge_id")?,
        kind: take_s(&item, "kind")?,
        state_json: take_s(&item, "state_json")?,
        email: item.get("email").and_then(|v| v.as_s().ok().cloned()),
        expires_at: take_s(&item, "expires_at")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0),
    };

    if row.kind != kind {
        return Err(AuthError::BadRequest(format!(
            "challenge kind mismatch: expected {kind}, got {}",
            row.kind
        )));
    }
    if row.expires_at != 0 && row.expires_at < now_secs() {
        return Err(AuthError::BadRequest("challenge expired".into()));
    }

    // Fire-and-forget delete so the challenge can't be reused.
    let _ = auth
        .dynamo
        .delete_item()
        .table_name(&auth.config.challenges_table)
        .key("challenge_id", AttributeValue::S(id.into()))
        .send()
        .await;

    Ok(row)
}

fn take_s(item: &HashMap<String, AttributeValue>, key: &str) -> AuthResult<String> {
    item.get(key)
        .and_then(|v| v.as_s().ok().cloned())
        .ok_or(AuthError::BadRequest(format!("missing attribute: {key}")))
}

pub async fn get_user_by_email(auth: &AuthState, email: &str) -> AuthResult<Option<UserRow>> {
    let out = auth
        .dynamo
        .get_item()
        .table_name(&auth.config.users_table)
        .key("email", AttributeValue::S(email.into()))
        .send()
        .await?;
    let Some(item) = out.item else { return Ok(None) };
    Ok(Some(UserRow {
        email: take_s(&item, "email")?,
        user_id: take_s(&item, "user_id")?,
        credential_id: take_s(&item, "credential_id")?,
        passkey_json: take_s(&item, "passkey_json")?,
        display_name: take_s(&item, "display_name").unwrap_or_default(),
        created_at: take_s(&item, "created_at")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0),
        storage_used_bytes: item
            .get("storage_used_bytes")
            .and_then(|v| v.as_n().ok())
            .and_then(|s| s.parse().ok()),
        pubkey_x25519_b64: item
            .get("pubkey_x25519_b64")
            .and_then(|v| v.as_s().ok().cloned()),
        wrapped_privkey_x25519_b64: item
            .get("wrapped_privkey_x25519_b64")
            .and_then(|v| v.as_s().ok().cloned()),
    }))
}

async fn put_user(auth: &AuthState, user: &UserRow) -> AuthResult<()> {
    let mut item: HashMap<String, AttributeValue> = HashMap::new();
    item.insert("email".into(), AttributeValue::S(user.email.clone()));
    item.insert("user_id".into(), AttributeValue::S(user.user_id.clone()));
    item.insert(
        "credential_id".into(),
        AttributeValue::S(user.credential_id.clone()),
    );
    item.insert(
        "passkey_json".into(),
        AttributeValue::S(user.passkey_json.clone()),
    );
    item.insert(
        "display_name".into(),
        AttributeValue::S(user.display_name.clone()),
    );
    item.insert(
        "created_at".into(),
        AttributeValue::N(user.created_at.to_string()),
    );
    // Initialize storage counter to zero at registration so later
    // conditional updates can rely on the attribute existing.
    item.insert("storage_used_bytes".into(), AttributeValue::N("0".into()));
    auth.dynamo
        .put_item()
        .table_name(&auth.config.users_table)
        .set_item(Some(item))
        // condition_expression ensures we don't clobber an existing row.
        .condition_expression("attribute_not_exists(email)")
        .send()
        .await
        .map_err(|e| {
            let msg = format!("{e}");
            if msg.contains("ConditionalCheckFailed") {
                AuthError::Conflict("email already registered".into())
            } else {
                AuthError::Dynamo(msg)
            }
        })?;
    Ok(())
}

// ────────────────────────────────────────────────────────────────────
//                          Handlers
// ────────────────────────────────────────────────────────────────────

const CHALLENGE_TTL_SECS: u64 = 300;

/// Per-user storage cap for the alpha. 100 MiB of committed `original_len`
/// bytes, which translates to ~150 MiB of raw shards after 4+2 Reed-Solomon
/// overhead. Enforced atomically in DynamoDB via a conditional `UpdateItem`
/// so concurrent commits can't race past it. Raise this, or make it
/// per-tier, once billing is wired up.
pub const QUOTA_BYTES: u64 = 100 * 1024 * 1024;

/// Outcome of a storage-consumption attempt.
#[derive(Debug)]
pub enum ConsumeStorageResult {
    Ok,
    Exceeded { used: u64, cap: u64, requested: u64 },
}

/// Atomically add `bytes` to a user's `storage_used_bytes` counter, or
/// return `Exceeded` if the addition would push them over `QUOTA_BYTES`.
/// Uses a single conditional UpdateItem so two concurrent commits can't
/// both see the same pre-update counter and both succeed.
///
/// Legacy user rows that don't have `storage_used_bytes` yet (written
/// before this feature landed) are treated as if they had 0 used — the
/// `attribute_not_exists` branch in the condition expression covers it.
pub async fn try_consume_storage(
    auth: &AuthState,
    email: &str,
    bytes: u64,
) -> AuthResult<ConsumeStorageResult> {
    if bytes > QUOTA_BYTES {
        return Ok(ConsumeStorageResult::Exceeded {
            used: 0,
            cap: QUOTA_BYTES,
            requested: bytes,
        });
    }
    let max_before: i64 = QUOTA_BYTES as i64 - bytes as i64;

    let result = auth
        .dynamo
        .update_item()
        .table_name(&auth.config.users_table)
        .key("email", AttributeValue::S(email.to_string()))
        .update_expression("ADD storage_used_bytes :delta")
        .condition_expression(
            "attribute_not_exists(storage_used_bytes) OR storage_used_bytes <= :max_before",
        )
        .expression_attribute_values(":delta", AttributeValue::N(bytes.to_string()))
        .expression_attribute_values(
            ":max_before",
            AttributeValue::N(max_before.to_string()),
        )
        .return_values(aws_sdk_dynamodb::types::ReturnValue::UpdatedNew)
        .send()
        .await;

    match result {
        Ok(_) => Ok(ConsumeStorageResult::Ok),
        Err(e) => {
            let msg = format!("{e:?}");
            if msg.contains("ConditionalCheckFailed") {
                // Read back the current usage so the client can show a
                // helpful "you're over" message instead of a bare 413.
                let used = get_user_by_email(auth, email)
                    .await?
                    .and_then(|u| u.storage_used_bytes)
                    .unwrap_or(0);
                Ok(ConsumeStorageResult::Exceeded {
                    used,
                    cap: QUOTA_BYTES,
                    requested: bytes,
                })
            } else {
                Err(AuthError::Dynamo(msg))
            }
        }
    }
}

/// Decrement a user's storage counter by `bytes`. Called after a
/// successful delete. Clamps at zero defensively — if the counter ever
/// drifts below what the manifests say (e.g. a half-applied delete
/// during a crash), we don't want it wrapping into u64::MAX.
pub async fn release_storage(auth: &AuthState, email: &str, bytes: u64) -> AuthResult<()> {
    // We ADD a negative delta. DynamoDB ADD on numbers is signed, so
    // this works. The condition ensures we never drop the counter
    // below zero — if storage_used_bytes < bytes, the counter is
    // clamped to 0 via a second write.
    let bytes_i: i64 = bytes as i64;
    let try_signed_add = auth
        .dynamo
        .update_item()
        .table_name(&auth.config.users_table)
        .key("email", AttributeValue::S(email.to_string()))
        .update_expression("ADD storage_used_bytes :delta")
        .condition_expression("storage_used_bytes >= :abs")
        .expression_attribute_values(":delta", AttributeValue::N((-bytes_i).to_string()))
        .expression_attribute_values(":abs", AttributeValue::N(bytes_i.to_string()))
        .send()
        .await;

    if let Err(e) = try_signed_add {
        let msg = format!("{e:?}");
        if msg.contains("ConditionalCheckFailed") {
            // Counter drift — reset to zero rather than panicking.
            let _ = auth
                .dynamo
                .update_item()
                .table_name(&auth.config.users_table)
                .key("email", AttributeValue::S(email.to_string()))
                .update_expression("SET storage_used_bytes = :zero")
                .expression_attribute_values(":zero", AttributeValue::N("0".into()))
                .send()
                .await;
            warn!(email = %email, bytes = %bytes, "storage counter drift — reset to 0");
        } else {
            return Err(AuthError::Dynamo(msg));
        }
    }
    Ok(())
}

pub async fn register_begin(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RegisterBeginRequest>,
) -> AuthResult<Json<RegisterBeginResponse>> {
    let auth = state.auth.as_ref().ok_or(AuthError::BadRequest(
        "auth not configured on this deployment".into(),
    ))?;
    let email = normalize_email(&req.email);
    if email.is_empty() || !email.contains('@') {
        return Err(AuthError::BadRequest("valid email required".into()));
    }

    // Reject if the email is already registered.
    if get_user_by_email(auth, &email).await?.is_some() {
        return Err(AuthError::Conflict("email already registered".into()));
    }

    let user_unique_id = Uuid::new_v4();
    let display_name = req
        .display_name
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or(&email);

    let (ccr, reg_state) = auth.webauthn.start_passkey_registration(
        user_unique_id,
        &email,
        display_name,
        None, // no exclude list — webauthn-rs uses the user's cred list elsewhere
    )?;

    let challenge_id = Uuid::new_v4().to_string();
    let state_json = serde_json::to_string(&reg_state)
        .map_err(|e| AuthError::Internal(anyhow::anyhow!("serialize reg state: {e}")))?;
    put_challenge(
        auth,
        &ChallengeRow {
            challenge_id: challenge_id.clone(),
            kind: "registration".into(),
            state_json,
            email: Some(email.clone()),
            expires_at: now_secs() + CHALLENGE_TTL_SECS,
        },
    )
    .await?;

    let creation_options = serde_json::to_value(&ccr)
        .map_err(|e| AuthError::Internal(anyhow::anyhow!("serialize ccr: {e}")))?;

    Ok(Json(RegisterBeginResponse {
        challenge_id,
        creation_options,
    }))
}

pub async fn register_finish(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RegisterFinishRequest>,
) -> AuthResult<Response> {
    let auth = state.auth.as_ref().ok_or(AuthError::BadRequest(
        "auth not configured on this deployment".into(),
    ))?;

    let challenge = take_challenge(auth, &req.challenge_id, "registration").await?;
    let reg_state: PasskeyRegistration = serde_json::from_str(&challenge.state_json)
        .map_err(|e| AuthError::Internal(anyhow::anyhow!("decode reg state: {e}")))?;

    let passkey = auth
        .webauthn
        .finish_passkey_registration(&req.credential, &reg_state)?;

    let email = challenge
        .email
        .ok_or(AuthError::Internal(anyhow::anyhow!(
            "registration challenge missing email"
        )))?;
    let display_name = email.clone();
    let credential_id = BASE64_URL_SAFE_NO_PAD.encode(passkey.cred_id().as_ref());
    let passkey_json = serde_json::to_string(&passkey)
        .map_err(|e| AuthError::Internal(anyhow::anyhow!("serialize passkey: {e}")))?;

    let user = UserRow {
        email: email.clone(),
        user_id: Uuid::new_v4().to_string(),
        credential_id,
        passkey_json,
        display_name,
        created_at: now_secs(),
        storage_used_bytes: Some(0),
        // Identity is minted lazily by the browser on the first
        // PRF-capable login right after registration finishes, via
        // PUT /auth/me/identity. Registration itself doesn't have
        // access to the master key yet (that lives client-side) so
        // we can't pre-seal a privkey here.
        pubkey_x25519_b64: None,
        wrapped_privkey_x25519_b64: None,
    };
    put_user(auth, &user).await?;

    info!(user_id = %user.user_id, email = %user.email, "registered passkey");

    let cookie = issue_session_cookie(&auth.config, &user)?;
    let body = SessionResponse {
        user_id: user.user_id.clone(),
        email: user.email.clone(),
        display_name: user.display_name.clone(),
    };
    Ok(session_response(cookie, body))
}

/// Start a discoverable-credential login (a.k.a. "usernameless" or
/// "conditional UI" sign-in). No email required — the server issues
/// an authentication challenge with empty allowCredentials and lets
/// the browser's credential picker decide which passkey to use. The
/// user is identified on finish from the returned credential's
/// user handle.
pub async fn login_begin_discoverable(
    State(state): State<Arc<AppState>>,
) -> AuthResult<Json<LoginBeginResponse>> {
    let auth = state.auth.as_ref().ok_or(AuthError::BadRequest(
        "auth not configured on this deployment".into(),
    ))?;

    let (rcr, discoverable_state) = auth.webauthn.start_discoverable_authentication()?;
    let state_json = serde_json::to_string(&discoverable_state)
        .map_err(|e| AuthError::Internal(anyhow::anyhow!("serialize disc state: {e}")))?;

    let challenge_id = Uuid::new_v4().to_string();
    put_challenge(
        auth,
        &ChallengeRow {
            challenge_id: challenge_id.clone(),
            kind: "discoverable".into(),
            state_json,
            email: None,
            expires_at: now_secs() + CHALLENGE_TTL_SECS,
        },
    )
    .await?;

    let request_options = serde_json::to_value(&rcr)
        .map_err(|e| AuthError::Internal(anyhow::anyhow!("serialize rcr: {e}")))?;

    Ok(Json(LoginBeginResponse {
        challenge_id,
        request_options,
    }))
}

/// Finish a discoverable-credential login. Identifies the user from
/// the returned credential via the credential_id GSI, then verifies
/// the assertion against that user's stored Passkey.
pub async fn login_finish_discoverable(
    State(state): State<Arc<AppState>>,
    Json(req): Json<LoginFinishRequest>,
) -> AuthResult<Response> {
    let auth = state.auth.as_ref().ok_or(AuthError::BadRequest(
        "auth not configured on this deployment".into(),
    ))?;

    let challenge = take_challenge(auth, &req.challenge_id, "discoverable").await?;
    let disc_state: DiscoverableAuthentication = serde_json::from_str(&challenge.state_json)
        .map_err(|e| AuthError::Internal(anyhow::anyhow!("decode disc state: {e}")))?;

    // Look up the user by credential_id. The browser returns the
    // credential's raw_id, which we encoded as base64url-no-pad at
    // registration time and indexed on the credential_id-index GSI.
    let credential_id_b64 = BASE64_URL_SAFE_NO_PAD.encode(req.credential.raw_id.as_ref());
    let user = get_user_by_credential_id(auth, &credential_id_b64).await?;
    let Some(user) = user else {
        return Err(AuthError::Unauthorized);
    };

    let passkey: Passkey = serde_json::from_str(&user.passkey_json)
        .map_err(|e| AuthError::Internal(anyhow::anyhow!("decode stored passkey: {e}")))?;

    // webauthn-rs finish_discoverable_authentication takes a slice of
    // DiscoverableKey tuples — (cred_id, Passkey) — to locate the
    // matching credential. We only expect one to match.
    let disc_keys = [webauthn_rs::prelude::DiscoverableKey::from(&passkey)];
    let _result = auth.webauthn.finish_discoverable_authentication(
        &req.credential,
        disc_state,
        &disc_keys,
    )?;

    info!(user_id = %user.user_id, "discoverable login success");

    let cookie = issue_session_cookie(&auth.config, &user)?;
    let body = SessionResponse {
        user_id: user.user_id.clone(),
        email: user.email.clone(),
        display_name: user.display_name.clone(),
    };
    Ok(session_response(cookie, body))
}

async fn get_user_by_credential_id(
    auth: &AuthState,
    credential_id_b64: &str,
) -> AuthResult<Option<UserRow>> {
    let out = auth
        .dynamo
        .query()
        .table_name(&auth.config.users_table)
        .index_name("credential_id-index")
        .key_condition_expression("credential_id = :cid")
        .expression_attribute_values(":cid", AttributeValue::S(credential_id_b64.to_string()))
        .limit(1)
        .send()
        .await?;
    let item = match out.items().first() {
        Some(i) => i.clone(),
        None => return Ok(None),
    };
    Ok(Some(UserRow {
        email: take_s(&item, "email")?,
        user_id: take_s(&item, "user_id")?,
        credential_id: take_s(&item, "credential_id")?,
        passkey_json: take_s(&item, "passkey_json")?,
        display_name: take_s(&item, "display_name").unwrap_or_default(),
        created_at: take_s(&item, "created_at")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0),
        storage_used_bytes: item
            .get("storage_used_bytes")
            .and_then(|v| v.as_n().ok())
            .and_then(|s| s.parse().ok()),
        pubkey_x25519_b64: item
            .get("pubkey_x25519_b64")
            .and_then(|v| v.as_s().ok().cloned()),
        wrapped_privkey_x25519_b64: item
            .get("wrapped_privkey_x25519_b64")
            .and_then(|v| v.as_s().ok().cloned()),
    }))
}

pub async fn login_begin(
    State(state): State<Arc<AppState>>,
    Json(req): Json<LoginBeginRequest>,
) -> AuthResult<Json<LoginBeginResponse>> {
    let auth = state.auth.as_ref().ok_or(AuthError::BadRequest(
        "auth not configured on this deployment".into(),
    ))?;
    let email = normalize_email(&req.email);
    let user = get_user_by_email(auth, &email).await?.ok_or_else(|| {
        // Don't leak enumeration info — just "not found" is enough, and
        // the client UI says "check your email or sign up".
        AuthError::NotFound
    })?;

    let passkey: Passkey = serde_json::from_str(&user.passkey_json)
        .map_err(|e| AuthError::Internal(anyhow::anyhow!("decode stored passkey: {e}")))?;

    let (rcr, auth_state_) = auth.webauthn.start_passkey_authentication(&[passkey])?;
    let state_json = serde_json::to_string(&auth_state_)
        .map_err(|e| AuthError::Internal(anyhow::anyhow!("serialize auth state: {e}")))?;

    let challenge_id = Uuid::new_v4().to_string();
    put_challenge(
        auth,
        &ChallengeRow {
            challenge_id: challenge_id.clone(),
            kind: "authentication".into(),
            state_json,
            email: Some(email.clone()),
            expires_at: now_secs() + CHALLENGE_TTL_SECS,
        },
    )
    .await?;

    let request_options = serde_json::to_value(&rcr)
        .map_err(|e| AuthError::Internal(anyhow::anyhow!("serialize rcr: {e}")))?;

    Ok(Json(LoginBeginResponse {
        challenge_id,
        request_options,
    }))
}

pub async fn login_finish(
    State(state): State<Arc<AppState>>,
    Json(req): Json<LoginFinishRequest>,
) -> AuthResult<Response> {
    let auth = state.auth.as_ref().ok_or(AuthError::BadRequest(
        "auth not configured on this deployment".into(),
    ))?;

    let challenge = take_challenge(auth, &req.challenge_id, "authentication").await?;
    let auth_state_: PasskeyAuthentication = serde_json::from_str(&challenge.state_json)
        .map_err(|e| AuthError::Internal(anyhow::anyhow!("decode auth state: {e}")))?;

    let _result = auth
        .webauthn
        .finish_passkey_authentication(&req.credential, &auth_state_)?;

    let email = challenge.email.ok_or(AuthError::Internal(anyhow::anyhow!(
        "auth challenge missing email"
    )))?;
    let user = get_user_by_email(auth, &email)
        .await?
        .ok_or(AuthError::NotFound)?;

    // NOTE: On successful finish webauthn-rs returns an AuthenticationResult
    // containing the new counter state. A production build should update
    // the stored Passkey with the new counter to detect cloned authenticators.
    // Passkey devices (platform authenticators) generally keep counter = 0
    // so this is rarely observed in practice — deferring until after MVP.

    info!(user_id = %user.user_id, "login success");

    let cookie = issue_session_cookie(&auth.config, &user)?;
    let body = SessionResponse {
        user_id: user.user_id.clone(),
        email: user.email.clone(),
        display_name: user.display_name.clone(),
    };
    Ok(session_response(cookie, body))
}

pub async fn me(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> AuthResult<Json<MeResponse>> {
    let auth = state.auth.as_ref().ok_or(AuthError::Unauthorized)?;
    // Read the row to get a fresh usage count. Cheap (single GetItem),
    // and only called on page load / tab focus — not on every vault op.
    let row = get_user_by_email(auth, &user.email).await?;
    let storage_used_bytes = row.as_ref().and_then(|u| u.storage_used_bytes).unwrap_or(0);
    let pubkey_x25519_b64 = row.as_ref().and_then(|u| u.pubkey_x25519_b64.clone());
    let wrapped_privkey_x25519_b64 =
        row.as_ref().and_then(|u| u.wrapped_privkey_x25519_b64.clone());
    Ok(Json(MeResponse {
        user_id: user.user_id,
        email: user.email,
        display_name: user.display_name,
        storage_used_bytes,
        storage_quota_bytes: QUOTA_BYTES,
        pubkey_x25519_b64,
        wrapped_privkey_x25519_b64,
    }))
}

/// `PUT /auth/me/identity` — one-time mint of the caller's long-term
/// X25519 identity. Called exactly once by the browser after the first
/// PRF-capable login on an account that has no identity yet. Both
/// fields are opaque base64 blobs produced client-side by
/// `x25519_generate_identity` (pubkey) + `encrypt_data` under the
/// master key (wrapped privkey).
///
/// Conditional on `attribute_not_exists(pubkey_x25519_b64)` so a later
/// call that tries to overwrite — whether accidentally, via a bug, or
/// via an attacker who somehow holds a session — is rejected with 409
/// Conflict. The identity is effectively an extension of the user's
/// passkey: stable forever, same blast radius on loss.
pub async fn set_identity(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<SetIdentityRequest>,
) -> AuthResult<Json<serde_json::Value>> {
    let auth = state.auth.as_ref().ok_or(AuthError::Unauthorized)?;

    // Light format validation. We deliberately don't validate the
    // *contents* of the wrapped privkey (the server can't decrypt it)
    // but we do gate the pubkey on a correct 32-byte x25519 key length
    // post-base64 to catch obvious client bugs before they write a
    // permanent row.
    let pk_bytes = BASE64_STANDARD
        .decode(req.pubkey_x25519_b64.trim())
        .map_err(|e| AuthError::BadRequest(format!("pubkey_x25519_b64 not base64: {e}")))?;
    if pk_bytes.len() != 32 {
        return Err(AuthError::BadRequest(format!(
            "pubkey_x25519_b64 must decode to 32 bytes, got {}",
            pk_bytes.len()
        )));
    }
    if req.wrapped_privkey_x25519_b64.trim().is_empty() {
        return Err(AuthError::BadRequest(
            "wrapped_privkey_x25519_b64 required".into(),
        ));
    }

    let result = auth
        .dynamo
        .update_item()
        .table_name(&auth.config.users_table)
        .key("email", AttributeValue::S(user.email.clone()))
        .update_expression(
            "SET pubkey_x25519_b64 = :pk, wrapped_privkey_x25519_b64 = :wsk",
        )
        .condition_expression("attribute_not_exists(pubkey_x25519_b64)")
        .expression_attribute_values(
            ":pk",
            AttributeValue::S(req.pubkey_x25519_b64.clone()),
        )
        .expression_attribute_values(
            ":wsk",
            AttributeValue::S(req.wrapped_privkey_x25519_b64.clone()),
        )
        .send()
        .await;

    match result {
        Ok(_) => {
            info!(user_id = %user.user_id, "x25519 identity minted");
            Ok(Json(serde_json::json!({
                "ok": true,
                "pubkey_x25519_b64": req.pubkey_x25519_b64,
            })))
        }
        Err(e) => {
            let msg = format!("{e:?}");
            if msg.contains("ConditionalCheckFailed") {
                Err(AuthError::Conflict(
                    "identity already established for this user".into(),
                ))
            } else {
                Err(AuthError::Dynamo(msg))
            }
        }
    }
}

/// `GET /users/lookup?email=X` — resolve another user's **public**
/// X25519 identity for the purpose of sharing an asset with them. The
/// caller must be authenticated; we refuse to expose identities to
/// unauthenticated scrapers even though the pubkeys themselves are
/// public crypto material, because the mapping `email -> has an
/// account` is itself a disclosure.
///
/// Returns 404 if the user doesn't exist OR if they haven't minted an
/// identity yet — we deliberately collapse both cases so an attacker
/// can't use this endpoint to probe which emails have RESQD accounts
/// without identities (vs. which don't have accounts at all).
pub async fn lookup_user(
    State(state): State<Arc<AppState>>,
    _caller: AuthUser,
    Query(q): Query<UserLookupQuery>,
) -> AuthResult<Json<UserLookupResponse>> {
    let auth = state.auth.as_ref().ok_or(AuthError::Unauthorized)?;
    let email = normalize_email(&q.email);
    if email.is_empty() || !email.contains('@') {
        return Err(AuthError::BadRequest("valid email required".into()));
    }

    let row = get_user_by_email(auth, &email).await?.ok_or(AuthError::NotFound)?;
    let pubkey = row
        .pubkey_x25519_b64
        .ok_or(AuthError::NotFound)?;

    Ok(Json(UserLookupResponse {
        user_id: row.user_id,
        email: row.email,
        display_name: row.display_name,
        pubkey_x25519_b64: pubkey,
    }))
}

#[derive(Deserialize)]
pub struct UserLookupQuery {
    pub email: String,
}

/// Lookup by user_id (not email). Used by handlers that only know the
/// opaque owner id — e.g. when a sharee fetches a shared asset and we
/// want to surface the sender's email/display name in the read path
/// without a second round trip. Scans by-email via a loose approach
/// for now; at scale we'd add a user_id GSI, but the alpha population
/// is small enough that a single targeted GetItem by email is the hot
/// path and this helper only runs on the sharing read, which is
/// already a multi-step flow.
pub async fn get_user_by_user_id(
    auth: &AuthState,
    user_id: &str,
) -> AuthResult<Option<UserRow>> {
    // For the alpha we take advantage of `user_id` being carried on
    // every token row and use the tokens GSI as a poor-man's reverse
    // lookup. This keeps us from having to add another GSI on the
    // users table just for sharing. If a user has no tokens we fall
    // back to scanning the users table — acceptable while the
    // population is tiny. Revisit when users table grows.
    let out = auth
        .dynamo
        .query()
        .table_name(&auth.config.tokens_table)
        .index_name("user_id-index")
        .key_condition_expression("user_id = :uid")
        .expression_attribute_values(":uid", AttributeValue::S(user_id.to_string()))
        .limit(1)
        .send()
        .await?;
    if let Some(tok) = out.items().first() {
        if let Ok(email) = take_s(tok, "email") {
            return get_user_by_email(auth, &email).await;
        }
    }
    // Fallback: scan the users table for a matching user_id. Linear in
    // the users table size — fine for alpha.
    let scan = auth
        .dynamo
        .scan()
        .table_name(&auth.config.users_table)
        .filter_expression("user_id = :uid")
        .expression_attribute_values(":uid", AttributeValue::S(user_id.to_string()))
        .limit(1)
        .send()
        .await?;
    if let Some(item) = scan.items().first() {
        return Ok(Some(UserRow {
            email: take_s(item, "email")?,
            user_id: take_s(item, "user_id")?,
            credential_id: take_s(item, "credential_id")?,
            passkey_json: take_s(item, "passkey_json")?,
            display_name: take_s(item, "display_name").unwrap_or_default(),
            created_at: take_s(item, "created_at")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0),
            storage_used_bytes: item
                .get("storage_used_bytes")
                .and_then(|v| v.as_n().ok())
                .and_then(|s| s.parse().ok()),
            pubkey_x25519_b64: item
                .get("pubkey_x25519_b64")
                .and_then(|v| v.as_s().ok().cloned()),
            wrapped_privkey_x25519_b64: item
                .get("wrapped_privkey_x25519_b64")
                .and_then(|v| v.as_s().ok().cloned()),
        }));
    }
    Ok(None)
}

// ────────────────────────────────────────────────────────────────────
//                       API token management
// ────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateTokenRequest {
    #[serde(default)]
    pub label: Option<String>,
}

#[derive(Serialize)]
pub struct CreateTokenResponse {
    /// The full raw token — `rsqd_...`. Only returned here, ONCE. The
    /// server stores only the SHA-256 hash, so if the user loses this
    /// value they must mint a new one.
    pub token: String,
    pub token_hash: String,
    pub label: String,
    pub created_at: u64,
}

#[derive(Serialize)]
pub struct TokenSummary {
    pub token_hash: String,
    pub label: String,
    pub created_at: u64,
    pub last_used_at: Option<u64>,
}

#[derive(Serialize)]
pub struct ListTokensResponse {
    pub count: usize,
    pub tokens: Vec<TokenSummary>,
}

fn generate_raw_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    format!("rsqd_{}", BASE64_URL_SAFE_NO_PAD.encode(bytes))
}

pub async fn create_token(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<CreateTokenRequest>,
) -> AuthResult<Json<CreateTokenResponse>> {
    let auth = state.auth.as_ref().ok_or(AuthError::BadRequest(
        "auth not configured on this deployment".into(),
    ))?;

    let raw = generate_raw_token();
    let token_hash = hash_token(&raw);
    let label = req
        .label
        .unwrap_or_else(|| "unnamed".to_string())
        .chars()
        .take(64)
        .collect::<String>();
    let created_at = now_secs();

    let mut item: HashMap<String, AttributeValue> = HashMap::new();
    item.insert("token_hash".into(), AttributeValue::S(token_hash.clone()));
    item.insert("user_id".into(), AttributeValue::S(user.user_id.clone()));
    item.insert("email".into(), AttributeValue::S(user.email.clone()));
    item.insert(
        "display_name".into(),
        AttributeValue::S(user.display_name.clone()),
    );
    item.insert("label".into(), AttributeValue::S(label.clone()));
    item.insert(
        "created_at".into(),
        AttributeValue::N(created_at.to_string()),
    );

    auth.dynamo
        .put_item()
        .table_name(&auth.config.tokens_table)
        .set_item(Some(item))
        .send()
        .await?;

    info!(user_id = %user.user_id, label = %label, "minted api token");

    Ok(Json(CreateTokenResponse {
        token: raw,
        token_hash,
        label,
        created_at,
    }))
}

pub async fn list_tokens(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> AuthResult<Json<ListTokensResponse>> {
    let auth = state.auth.as_ref().ok_or(AuthError::BadRequest(
        "auth not configured on this deployment".into(),
    ))?;

    let out = auth
        .dynamo
        .query()
        .table_name(&auth.config.tokens_table)
        .index_name("user_id-index")
        .key_condition_expression("user_id = :uid")
        .expression_attribute_values(":uid", AttributeValue::S(user.user_id.clone()))
        .send()
        .await?;

    let tokens: Vec<TokenSummary> = out
        .items()
        .iter()
        .map(|item| TokenSummary {
            token_hash: take_s(item, "token_hash").unwrap_or_default(),
            label: take_s(item, "label").unwrap_or_default(),
            created_at: take_s(item, "created_at")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0),
            last_used_at: take_s(item, "last_used_at")
                .ok()
                .and_then(|s| s.parse().ok()),
        })
        .collect();

    Ok(Json(ListTokensResponse {
        count: tokens.len(),
        tokens,
    }))
}

pub async fn revoke_token(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    axum::extract::Path(token_hash): axum::extract::Path<String>,
) -> AuthResult<Json<serde_json::Value>> {
    let auth = state.auth.as_ref().ok_or(AuthError::BadRequest(
        "auth not configured on this deployment".into(),
    ))?;

    // Verify the token belongs to the authed user before deleting it.
    // Otherwise any authed user could DELETE /auth/tokens/<hash> to
    // revoke someone else's token.
    let out = auth
        .dynamo
        .get_item()
        .table_name(&auth.config.tokens_table)
        .key("token_hash", AttributeValue::S(token_hash.clone()))
        .send()
        .await?;
    let item = out.item.ok_or(AuthError::NotFound)?;
    let owner = take_s(&item, "user_id")?;
    if owner != user.user_id {
        return Err(AuthError::NotFound);
    }

    auth.dynamo
        .delete_item()
        .table_name(&auth.config.tokens_table)
        .key("token_hash", AttributeValue::S(token_hash.clone()))
        .send()
        .await?;

    info!(user_id = %user.user_id, token_hash = %token_hash, "revoked api token");

    Ok(Json(serde_json::json!({ "revoked": true })))
}

pub async fn logout(State(state): State<Arc<AppState>>) -> AuthResult<Response> {
    let auth = state.auth.as_ref().ok_or(AuthError::BadRequest(
        "auth not configured on this deployment".into(),
    ))?;
    let cookie = clear_session_cookie(&auth.config);
    let mut resp = Json(serde_json::json!({"ok": true})).into_response();
    resp.headers_mut()
        .insert(header::SET_COOKIE, cookie.parse().unwrap());
    Ok(resp)
}

fn session_response<T: Serialize>(cookie: String, body: T) -> Response {
    let mut resp = Json(body).into_response();
    resp.headers_mut().insert(
        header::SET_COOKIE,
        cookie
            .parse()
            .unwrap_or_else(|_| "resqd_session=".parse().unwrap()),
    );
    resp
}

/// Idle timeout — how long a cookie is considered "fresh" even when not
/// refreshed. Currently the same as `session_ttl_secs`; kept as a separate
/// constant so we can later distinguish "authenticated" from "recently
/// active" without breaking callers.
pub const _SESSION_IDLE_SECS: u64 = 7 * 24 * 3600;

#[allow(dead_code)]
fn _force_imports() {
    // Silence unused-import warnings for types that only appear in trait
    // bound positions above.
    let _: Duration = Duration::from_secs(0);
}
