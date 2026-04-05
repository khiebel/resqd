/**
 * Passkey client for RESQD.
 *
 * Runs the WebAuthn registration and authentication ceremonies with the
 * PRF extension enabled. The PRF output is used client-side to derive
 * the vault master key — the server never sees any key material.
 *
 * Design notes:
 *
 * - The server returns the raw webauthn-rs `CreationChallengeResponse` /
 *   `RequestChallengeResponse` JSON. We deep-convert its base64url fields
 *   into `Uint8Array`s so the browser's `navigator.credentials` API
 *   accepts them, then inject our PRF extension into `extensions`.
 * - The PRF salt is a fixed per-app constant, not per-user. PRF output
 *   is already unique per credential (that's the whole point of PRF),
 *   so a constant salt is sufficient to give every user a unique key.
 *   The salt is public; it's encoded into the client bundle.
 * - The PRF output comes back in `credential.getClientExtensionResults().prf.results.first`
 *   as an `ArrayBuffer`. We stash it in `sessionStorage` under
 *   `resqd_master_key` so upload/fetch pages can reuse it without
 *   re-prompting for biometrics on every asset operation.
 */

import { API_URL, getCrypto, base64ToBytes, bytesToBase64 } from "./resqdCrypto";

/** Fixed 32-byte salt for the PRF `eval.first` input. Public by design. */
export const PRF_SALT = new Uint8Array([
  0x52, 0x45, 0x53, 0x51, 0x44, 0x2d, 0x76, 0x61, 0x75, 0x6c, 0x74, 0x2d,
  0x70, 0x72, 0x66, 0x2d, 0x76, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
]);

const MASTER_KEY_STORAGE = "resqd_master_key";
const X25519_PRIVKEY_STORAGE = "resqd_x25519_privkey";
const X25519_PUBKEY_STORAGE = "resqd_x25519_pubkey";

export interface SessionUser {
  user_id: string;
  email: string;
  display_name: string;
  /** Populated by /auth/me (not by the login/signup responses). */
  storage_used_bytes?: number;
  storage_quota_bytes?: number;
}

// ── Base64url helpers ────────────────────────────────────────────────

export function b64uToBytes(b64u: string): Uint8Array {
  const b64 = b64u.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64 + "===".slice((b64.length + 3) % 4);
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function bytesToB64u(bytes: Uint8Array | ArrayBuffer): string {
  const u = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let bin = "";
  for (let i = 0; i < u.length; i++) bin += String.fromCharCode(u[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// ── Server-JSON ⇌ BufferSource conversion ────────────────────────────
//
// webauthn-rs serializes every binary field as a base64url string. The
// browser needs `BufferSource` in every binary slot. These helpers walk
// the known WebAuthn schema and convert in both directions.

function toCreationOptions(
  json: Record<string, unknown>,
): PublicKeyCredentialCreationOptions {
  const pk = { ...(json.publicKey as Record<string, unknown>) };
  pk.challenge = b64uToBytes(pk.challenge as string);
  const user = { ...(pk.user as Record<string, unknown>) };
  user.id = b64uToBytes(user.id as string);
  pk.user = user;
  if (Array.isArray(pk.excludeCredentials)) {
    pk.excludeCredentials = (pk.excludeCredentials as Record<string, unknown>[]).map(
      (c) => ({ ...c, id: b64uToBytes(c.id as string) }),
    );
  }
  return pk as unknown as PublicKeyCredentialCreationOptions;
}

function toRequestOptions(
  json: Record<string, unknown>,
): PublicKeyCredentialRequestOptions {
  const pk = { ...(json.publicKey as Record<string, unknown>) };
  pk.challenge = b64uToBytes(pk.challenge as string);
  if (Array.isArray(pk.allowCredentials)) {
    pk.allowCredentials = (pk.allowCredentials as Record<string, unknown>[]).map(
      (c) => ({ ...c, id: b64uToBytes(c.id as string) }),
    );
  }
  return pk as unknown as PublicKeyCredentialRequestOptions;
}

/** Serialize a `PublicKeyCredential` from `navigator.credentials.create` back
 *  into the JSON shape `webauthn-rs`'s `RegisterPublicKeyCredential` expects. */
function fromRegistrationCredential(
  cred: PublicKeyCredential,
): Record<string, unknown> {
  const attestation = cred.response as AuthenticatorAttestationResponse;
  return {
    id: cred.id,
    rawId: bytesToB64u(cred.rawId),
    type: cred.type,
    response: {
      attestationObject: bytesToB64u(attestation.attestationObject),
      clientDataJSON: bytesToB64u(attestation.clientDataJSON),
    },
    extensions: cred.getClientExtensionResults() as Record<string, unknown>,
  };
}

/** Serialize a `PublicKeyCredential` from `navigator.credentials.get` back
 *  into the JSON shape `webauthn-rs`'s `PublicKeyCredential` expects. */
function fromAuthenticationCredential(
  cred: PublicKeyCredential,
): Record<string, unknown> {
  const assertion = cred.response as AuthenticatorAssertionResponse;
  return {
    id: cred.id,
    rawId: bytesToB64u(cred.rawId),
    type: cred.type,
    response: {
      authenticatorData: bytesToB64u(assertion.authenticatorData),
      clientDataJSON: bytesToB64u(assertion.clientDataJSON),
      signature: bytesToB64u(assertion.signature),
      userHandle: assertion.userHandle ? bytesToB64u(assertion.userHandle) : null,
    },
    extensions: cred.getClientExtensionResults() as Record<string, unknown>,
  };
}

// ── PRF ─────────────────────────────────────────────────────────────

interface PrfExtensionResults {
  results?: { first?: ArrayBuffer };
}

function extractPrfKey(cred: PublicKeyCredential): Uint8Array | null {
  const ext = cred.getClientExtensionResults() as {
    prf?: PrfExtensionResults;
  };
  const buf = ext.prf?.results?.first;
  return buf ? new Uint8Array(buf) : null;
}

export function saveMasterKey(key: Uint8Array): void {
  sessionStorage.setItem(MASTER_KEY_STORAGE, bytesToB64u(key));
}

export function loadMasterKey(): Uint8Array | null {
  const v = sessionStorage.getItem(MASTER_KEY_STORAGE);
  return v ? b64uToBytes(v) : null;
}

export function clearMasterKey(): void {
  sessionStorage.removeItem(MASTER_KEY_STORAGE);
  sessionStorage.removeItem(X25519_PRIVKEY_STORAGE);
  sessionStorage.removeItem(X25519_PUBKEY_STORAGE);
}

/** Stash the unwrapped X25519 private identity (standard base64). Lives in
 *  sessionStorage next to the master key so sharing operations don't need
 *  to re-prompt for biometrics on every action. */
export function saveX25519Privkey(privB64: string, pubB64: string): void {
  sessionStorage.setItem(X25519_PRIVKEY_STORAGE, privB64);
  sessionStorage.setItem(X25519_PUBKEY_STORAGE, pubB64);
}

export function loadX25519Identity(): { privB64: string; pubB64: string } | null {
  const priv = sessionStorage.getItem(X25519_PRIVKEY_STORAGE);
  const pub = sessionStorage.getItem(X25519_PUBKEY_STORAGE);
  return priv && pub ? { privB64: priv, pubB64: pub } : null;
}

/**
 * Ensure the logged-in user has a long-term X25519 identity, and cache
 * the unwrapped private half in sessionStorage. Called immediately
 * after every successful passkey ceremony — registration or login —
 * while the caller still holds the fresh PRF-derived master key in
 * memory. On return, `loadX25519Identity()` will yield a usable pair.
 *
 * Three cases:
 *
 * 1. **Existing identity on the server.** Fetch `/auth/me`, unwrap the
 *    sealed privkey with the master key, stash both halves in session.
 *
 * 2. **No identity yet.** Generate a fresh keypair in WASM, seal the
 *    privkey under the master key via the standard XChaCha20 envelope,
 *    `PUT /auth/me/identity`. Conditional on server side so a second
 *    parallel tab racing the same mint will lose with 409 — in that
 *    case we refetch and use whatever's now on file.
 *
 * 3. **Master key doesn't yet wrap the stored privkey** (should never
 *    happen in practice — would mean the master key rotated, which we
 *    don't support). Logs a warning and continues without identity.
 */
async function ensureIdentity(masterKey: Uint8Array): Promise<void> {
  try {
    const crypto = await getCrypto();

    const meResp = await fetch(`${API_URL}/auth/me`, { credentials: "include" });
    if (!meResp.ok) return;
    const me = (await meResp.json()) as {
      pubkey_x25519_b64?: string | null;
      wrapped_privkey_x25519_b64?: string | null;
    };

    if (me.pubkey_x25519_b64 && me.wrapped_privkey_x25519_b64) {
      try {
        const wrappedJson = atob(me.wrapped_privkey_x25519_b64);
        const privBytes = crypto.decrypt_data(masterKey, wrappedJson);
        saveX25519Privkey(bytesToBase64(privBytes), me.pubkey_x25519_b64);
        return;
      } catch (e) {
        console.warn(
          "stored x25519 privkey does not unwrap under current master key:",
          e,
        );
        return;
      }
    }

    // Mint path. `x25519_generate_identity` returns JSON with base64
    // halves; the public half is uploaded in the clear and the
    // private half is sealed under the master key first.
    const identJson = crypto.x25519_generate_identity();
    const ident = JSON.parse(identJson) as {
      public_b64: string;
      private_b64: string;
    };
    const privBytes = base64ToBytes(ident.private_b64);
    const wrappedJson = crypto.encrypt_data(masterKey, privBytes);
    const wrappedB64 = btoa(wrappedJson);

    const putResp = await fetch(`${API_URL}/auth/me/identity`, {
      method: "PUT",
      credentials: "include",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        pubkey_x25519_b64: ident.public_b64,
        wrapped_privkey_x25519_b64: wrappedB64,
      }),
    });

    if (putResp.ok) {
      saveX25519Privkey(ident.private_b64, ident.public_b64);
      return;
    }

    // 409 = we lost a race with another tab. Refetch and use whatever
    // the server now holds (should be the other tab's keypair, which
    // is ALSO wrapped under the same master key since master keys are
    // stable per user, so it unwraps fine here).
    if (putResp.status === 409) {
      const meResp2 = await fetch(`${API_URL}/auth/me`, {
        credentials: "include",
      });
      if (meResp2.ok) {
        const me2 = (await meResp2.json()) as {
          pubkey_x25519_b64?: string | null;
          wrapped_privkey_x25519_b64?: string | null;
        };
        if (me2.pubkey_x25519_b64 && me2.wrapped_privkey_x25519_b64) {
          try {
            const wrappedJson2 = atob(me2.wrapped_privkey_x25519_b64);
            const privBytes2 = crypto.decrypt_data(masterKey, wrappedJson2);
            saveX25519Privkey(
              bytesToBase64(privBytes2),
              me2.pubkey_x25519_b64,
            );
            return;
          } catch (e) {
            console.warn("race-winner x25519 privkey does not unwrap:", e);
          }
        }
      }
      return;
    }

    console.warn(
      "x25519 identity mint failed:",
      putResp.status,
      await putResp.text(),
    );
  } catch (e) {
    // Identity is optional — a failure here leaves the user able to
    // use their own vault (master-key crypto is unaffected) but unable
    // to share. Surface as a console warning only.
    console.warn("ensureIdentity failed:", e);
  }
}

export function isPasskeySupported(): boolean {
  return (
    typeof window !== "undefined" &&
    typeof window.PublicKeyCredential !== "undefined" &&
    typeof navigator.credentials?.create === "function"
  );
}

// ── Public flows ────────────────────────────────────────────────────

/** Sign up with a fresh passkey. Returns the session user and stashes
 *  the PRF-derived master key in sessionStorage. */
export async function registerWithPasskey(email: string): Promise<SessionUser> {
  if (!isPasskeySupported()) {
    throw new Error("passkeys are not supported in this browser");
  }

  const beginResp = await fetch(`${API_URL}/auth/register/begin`, {
    method: "POST",
    credentials: "include",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email }),
  });
  if (!beginResp.ok) throw new Error(await readError(beginResp));
  const begin = await beginResp.json();

  const creationOptions = toCreationOptions(begin.creation_options);

  // Force a *discoverable* (resident) credential. webauthn-rs 0.5 defaults
  // to residentKey: "discouraged" on start_passkey_registration, which
  // means some platform authenticators create a non-discoverable
  // credential that can't be surfaced in fresh browser windows or across
  // devices via iCloud Keychain sync. Forcing "required" here is the
  // difference between "click a button and your passkey shows up" and
  // "wait, where did my passkey go".
  (creationOptions as unknown as {
    authenticatorSelection: Record<string, unknown>;
  }).authenticatorSelection = {
    ...((creationOptions as unknown as {
      authenticatorSelection?: Record<string, unknown>;
    }).authenticatorSelection ?? {}),
    requireResidentKey: true,
    residentKey: "required",
    // `platform` = Touch ID / Windows Hello / Android biometric. Restricts
    // the browser save dialog to the platform authenticator instead of
    // offering external security keys. On macOS Chrome this encourages
    // (but does not force) saving to iCloud Keychain so the credential
    // is visible to Safari too.
    authenticatorAttachment: "platform",
  };

  // Inject PRF extension. WebAuthn spec says the authenticator returns a
  // symmetric secret derived from `eval.first`; PRF outputs are stable
  // for a given (credential, salt) pair, so this is what gives us a
  // deterministic master key tied to the user's passkey.
  (creationOptions as unknown as { extensions: Record<string, unknown> }).extensions = {
    ...((creationOptions as unknown as { extensions?: Record<string, unknown> })
      .extensions ?? {}),
    prf: { eval: { first: PRF_SALT } },
  };

  const cred = (await navigator.credentials.create({
    publicKey: creationOptions,
  })) as PublicKeyCredential | null;
  if (!cred) throw new Error("passkey creation was cancelled");

  const prfKey = extractPrfKey(cred);
  if (!prfKey) {
    throw new Error(
      "your authenticator does not support the PRF extension — try a platform authenticator (Touch ID, Windows Hello) in Chrome or Safari",
    );
  }
  saveMasterKey(prfKey);

  const finishResp = await fetch(`${API_URL}/auth/register/finish`, {
    method: "POST",
    credentials: "include",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      challenge_id: begin.challenge_id,
      credential: fromRegistrationCredential(cred),
    }),
  });
  if (!finishResp.ok) throw new Error(await readError(finishResp));
  const session = (await finishResp.json()) as SessionUser;
  await ensureIdentity(prfKey);
  return session;
}

/** Log in with an existing passkey. */
export async function loginWithPasskey(email: string): Promise<SessionUser> {
  if (!isPasskeySupported()) {
    throw new Error("passkeys are not supported in this browser");
  }

  const beginResp = await fetch(`${API_URL}/auth/login/begin`, {
    method: "POST",
    credentials: "include",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email }),
  });
  if (!beginResp.ok) throw new Error(await readError(beginResp));
  const begin = await beginResp.json();

  const requestOptions = toRequestOptions(begin.request_options);
  (requestOptions as unknown as { extensions: Record<string, unknown> }).extensions = {
    ...((requestOptions as unknown as { extensions?: Record<string, unknown> })
      .extensions ?? {}),
    prf: { eval: { first: PRF_SALT } },
  };

  const cred = (await navigator.credentials.get({
    publicKey: requestOptions,
  })) as PublicKeyCredential | null;
  if (!cred) throw new Error("passkey login was cancelled");

  const prfKey = extractPrfKey(cred);
  if (!prfKey) {
    throw new Error("your authenticator did not return a PRF output");
  }
  saveMasterKey(prfKey);

  const finishResp = await fetch(`${API_URL}/auth/login/finish`, {
    method: "POST",
    credentials: "include",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      challenge_id: begin.challenge_id,
      credential: fromAuthenticationCredential(cred),
    }),
  });
  if (!finishResp.ok) throw new Error(await readError(finishResp));
  const session = (await finishResp.json()) as SessionUser;
  await ensureIdentity(prfKey);
  return session;
}

/** Start a conditional-UI sign-in. Runs navigator.credentials.get() with
 *  `mediation: "conditional"` so the browser autofills passkeys inline
 *  in any `autocomplete="username webauthn"` field on the page. Returns
 *  the signed-in user if the flow completes, or `null` if the user
 *  dismissed the picker / the browser doesn't support conditional UI. */
export async function loginWithPasskeyConditional(
  abortSignal?: AbortSignal,
): Promise<SessionUser | null> {
  if (!isPasskeySupported()) return null;

  // Some browsers expose `isConditionalMediationAvailable`. If they do
  // and it says no, don't even try — we'll fall back to the typed-email
  // flow. If they don't expose it, assume yes and let the browser
  // decide.
  const pkc = window.PublicKeyCredential as unknown as {
    isConditionalMediationAvailable?: () => Promise<boolean>;
  };
  if (pkc.isConditionalMediationAvailable) {
    try {
      if (!(await pkc.isConditionalMediationAvailable())) return null;
    } catch {
      return null;
    }
  }

  const beginResp = await fetch(`${API_URL}/auth/login/begin_discoverable`, {
    method: "POST",
    credentials: "include",
    headers: { "content-type": "application/json" },
    body: "{}",
  });
  if (!beginResp.ok) return null;
  const begin = await beginResp.json();

  const requestOptions = toRequestOptions(begin.request_options);
  (requestOptions as unknown as { extensions: Record<string, unknown> }).extensions = {
    ...((requestOptions as unknown as { extensions?: Record<string, unknown> })
      .extensions ?? {}),
    prf: { eval: { first: PRF_SALT } },
  };

  let cred: PublicKeyCredential | null;
  try {
    cred = (await navigator.credentials.get({
      publicKey: requestOptions,
      mediation: "conditional" as CredentialMediationRequirement,
      signal: abortSignal,
    } as CredentialRequestOptions)) as PublicKeyCredential | null;
  } catch (e) {
    // AbortError is expected when the user navigates away or submits
    // the form before picking a passkey. Don't surface as an error.
    if (e instanceof DOMException && e.name === "AbortError") return null;
    return null;
  }
  if (!cred) return null;

  const prfKey = extractPrfKey(cred);
  if (prfKey) {
    saveMasterKey(prfKey);
  }

  const finishResp = await fetch(`${API_URL}/auth/login/finish_discoverable`, {
    method: "POST",
    credentials: "include",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      challenge_id: begin.challenge_id,
      credential: fromAuthenticationCredential(cred),
    }),
  });
  if (!finishResp.ok) return null;
  const session = (await finishResp.json()) as SessionUser;
  if (prfKey) await ensureIdentity(prfKey);
  return session;
}

export async function fetchMe(): Promise<SessionUser | null> {
  try {
    const r = await fetch(`${API_URL}/auth/me`, { credentials: "include" });
    if (r.status === 401) return null;
    if (!r.ok) return null;
    return (await r.json()) as SessionUser;
  } catch {
    return null;
  }
}

export async function logout(): Promise<void> {
  try {
    await fetch(`${API_URL}/auth/logout`, {
      method: "POST",
      credentials: "include",
    });
  } finally {
    clearMasterKey();
  }
}

async function readError(resp: Response): Promise<string> {
  try {
    const j = (await resp.json()) as { error?: string };
    return j.error ?? `${resp.status} ${resp.statusText}`;
  } catch {
    return `${resp.status} ${resp.statusText}`;
  }
}
