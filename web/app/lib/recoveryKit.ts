/**
 * Recovery Kit — the "data of last resort" export.
 *
 * Produces a single self-contained JSON file that, combined with the
 * open-source `resqd-recover` CLI, lets the user reconstruct every
 * file they own or have been shared WITHOUT any dependency on
 * resqd.ai being alive. If the business disappears, the domain
 * lapses, the S3 bucket is reclaimed, and the API server is
 * unreachable, the user's Recovery Kit on disk is still enough to
 * get their data back.
 *
 * The kit is also the hand-off point for future paid recovery
 * products — it carries URLs for a DIY path (free), a paid concierge
 * path (future), and a post-mortem heir path (future), so the
 * business has a natural chargeable service layered over a
 * cryptographically-guaranteed free floor.
 *
 * # Format (version 1)
 *
 * Single JSON file with embedded base64 ciphertext shards. Intentionally
 * not a ZIP to keep the recovery tool dependency-free — any language
 * with `serde_json` (or `json.loads`) can walk it, verify it, and run
 * the decrypt pipeline.
 *
 * The file is large-ish for the alpha 100MB quota (~150MB of base64
 * text per user) but that's completely fine for a once-a-month
 * offline backup artifact.
 *
 * See `docs/RECOVERY_KIT_SPEC.md` for the authoritative format
 * description and the step-by-step decrypt algorithm.
 */

import {
  API_URL,
  base64ToBytes,
  bytesToBase64,
  getCrypto,
} from "./resqdCrypto";
import { bytesToB64u, loadMasterKey, loadX25519Identity } from "./passkey";
import { entropyToMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";

/** Recovery Kit format version currently emitted. */
export const RECOVERY_KIT_VERSION = 1;

/** URL of the format specification document in the public repo. */
export const RECOVERY_KIT_SPEC_URL =
  "https://github.com/khiebel/resqd/blob/main/docs/RECOVERY_KIT_SPEC.md";

export interface RecoveryKitAsset {
  asset_id: string;
  role: "owner" | "sharee" | "ring_member";
  /** Filename recovered from the asset frame header. May be null for
   *  legacy/no-name uploads. */
  filename: string | null;
  mime: string | null;
  /** Sharee-only: email of the user who shared this asset with us. */
  shared_by_email?: string | null;
  created_at: number;
  crypto: {
    aead: "xchacha20-poly1305";
    /** Per-asset XChaCha20 key, 32 bytes base64. UNWRAPPED and ready
     *  to feed directly into the decrypt step. */
    per_asset_key_b64: string;
    /** Framed plaintext format — the recover tool strips the header
     *  before writing the output file. Currently always
     *  "resqd-frame-v1" (u32 LE header_len || JSON header || body). */
    frame_format: "resqd-frame-v1";
  };
  erasure: {
    /** Data shards (required to reconstruct). */
    k: number;
    /** Total shards. */
    n: number;
    /** Byte length of the pre-erasure-coded ciphertext. */
    original_len: number;
  };
  /** Exactly `n` entries; missing shards (if any were lost) are
   *  emitted as `ciphertext_b64: null` and the recover tool will
   *  reconstruct as long as at least `k` remain. */
  shards: Array<{ index: number; ciphertext_b64: string | null }>;
}

export interface RecoveryKit {
  version: typeof RECOVERY_KIT_VERSION;
  spec_url: string;
  generated_at: number;
  recovery_tool: {
    cli_name: "resqd-recover";
    install_hint: string;
    source_url: string;
  };
  /** Pointers for the three ways to get data back. The DIY path is
   *  always available (it's just running the open-source tool against
   *  this file); the others are planned paid products. */
  recovery_service: {
    diy_url: string;
    concierge_url: string;
    heir_claim_url: string;
  };
  user: {
    user_id: string;
    email: string;
    /** PRF-derived vault master key, 32 bytes, standard base64. The
     *  Recovery Kit IS the last-resort artifact, so we include the
     *  master key in plaintext inside it — the user is responsible
     *  for storing the kit itself somewhere safe. */
    master_key_b64: string;
    /** BIP-39 mnemonic (24 words) encoding the master key for paper backup. */
    master_key_mnemonic: string;
    x25519_pubkey_b64: string;
    x25519_privkey_b64: string;
  };
  assets: RecoveryKitAsset[];
}

interface VaultListItem {
  asset_id: string;
  created_at: number;
  encrypted_meta_b64?: string | null;
  role?: "owner" | "sharee" | "ring_member";
  shared_by_email?: string | null;
  sender_pubkey_x25519_b64?: string | null;
  ring_id?: string | null;
  uploader_pubkey_x25519_b64?: string | null;
}

interface VaultListResponse {
  user_id: string;
  count: number;
  assets: VaultListItem[];
}

interface ShardedFetchResponse {
  mode: "sharded";
  asset_id: string;
  original_len: number;
  data_shards: number;
  parity_shards: number;
  shards: { index: number; download_url: string | null }[];
  canary_sequence: number;
  canary_hash_hex: string;
  ttl_seconds: number;
  role?: "owner" | "sharee" | "ring_member";
  wrapped_key_b64?: string;
  encrypted_meta_b64?: string;
  sender_pubkey_x25519_b64?: string;
  ring_id?: string;
  uploader_pubkey_x25519_b64?: string;
}

export interface ExportProgress {
  phase:
    | "init"
    | "listing"
    | "asset"
    | "shard"
    | "finalizing"
    | "done"
    | "error";
  /** For "asset" and "shard" phases: 1-indexed current / total. */
  current?: number;
  total?: number;
  label?: string;
  error?: string;
}

/**
 * Main entry point: build a Recovery Kit for the currently logged-in
 * user, trigger a download, and stream progress to `onProgress`.
 *
 * Caller requirements:
 * - User is signed in (valid session cookie)
 * - `loadMasterKey()` returns the PRF-derived master key
 * - `loadX25519Identity()` returns the unwrapped X25519 identity
 *   (established at login)
 *
 * Everything runs in the browser. The server sees only the standard
 * vault read flow (listing + per-asset manifest fetch + presigned
 * shard GETs); nothing new is exposed.
 *
 * Note: each asset fetch rotates its canary chain on the server. This
 * is expected — canary rotations are the audit trail, and a Recovery
 * Kit export counts as a legitimate read of every asset.
 */
export async function exportRecoveryKit(
  onProgress: (p: ExportProgress) => void,
): Promise<void> {
  const masterKey = loadMasterKey();
  const ident = loadX25519Identity();
  if (!masterKey) {
    onProgress({ phase: "error", error: "master key not loaded — sign in again" });
    return;
  }
  if (!ident) {
    onProgress({
      phase: "error",
      error: "X25519 identity not loaded — sign in again",
    });
    return;
  }

  onProgress({ phase: "init" });
  const crypto = await getCrypto();

  // User info from /auth/me.
  const meResp = await fetch(`${API_URL}/auth/me`, { credentials: "include" });
  if (!meResp.ok) {
    onProgress({ phase: "error", error: `/auth/me ${meResp.status}` });
    return;
  }
  const me = (await meResp.json()) as {
    user_id: string;
    email: string;
  };

  // Full vault listing (owned + shared).
  onProgress({ phase: "listing" });
  const listResp = await fetch(`${API_URL}/vault`, { credentials: "include" });
  if (!listResp.ok) {
    onProgress({ phase: "error", error: `/vault ${listResp.status}` });
    return;
  }
  const list = (await listResp.json()) as VaultListResponse;

  const kitAssets: RecoveryKitAsset[] = [];
  const total = list.assets.length;
  for (let i = 0; i < list.assets.length; i++) {
    const item = list.assets[i];
    onProgress({
      phase: "asset",
      current: i + 1,
      total,
      label: item.asset_id,
    });

    try {
      const kitAsset = await exportOneAsset({
        item,
        crypto,
        masterKey,
        identPrivB64: ident.privB64,
        onProgress: (p) => onProgress(p),
      });
      kitAssets.push(kitAsset);
    } catch (e) {
      console.warn(`export failed for ${item.asset_id}:`, e);
      // Skip the asset and keep going — partial kit is still useful.
    }
  }

  onProgress({ phase: "finalizing" });

  const kit: RecoveryKit = {
    version: RECOVERY_KIT_VERSION,
    spec_url: RECOVERY_KIT_SPEC_URL,
    generated_at: Math.floor(Date.now() / 1000),
    recovery_tool: {
      cli_name: "resqd-recover",
      install_hint:
        "cargo install --git https://github.com/khiebel/resqd resqd-recover",
      source_url: "https://github.com/khiebel/resqd",
    },
    recovery_service: {
      diy_url: "https://github.com/khiebel/resqd#recovery",
      // Future paid flows. The kit carries these forward so when we
      // stand up the endpoints users who minted kits today can still
      // click through — no migration required.
      concierge_url: "https://resqd.ai/recover",
      heir_claim_url: "https://resqd.ai/heir",
    },
    user: {
      user_id: me.user_id,
      email: me.email,
      master_key_b64: bytesToB64u(masterKey),
      master_key_mnemonic: entropyToMnemonic(masterKey, wordlist),
      x25519_pubkey_b64: ident.pubB64,
      x25519_privkey_b64: ident.privB64,
    },
    assets: kitAssets,
  };

  const json = JSON.stringify(kit, null, 2);
  const blob = new Blob([json], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const now = new Date();
  const stamp = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, "0")}-${String(
    now.getDate(),
  ).padStart(2, "0")}`;
  const emailSlug = me.email.replace(/[^a-z0-9]+/gi, "_");
  const filename = `resqd-recovery-kit-${emailSlug}-${stamp}.json`;

  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);

  onProgress({ phase: "done", current: total, total });
}

async function exportOneAsset(args: {
  item: VaultListItem;
  crypto: Awaited<ReturnType<typeof getCrypto>>;
  masterKey: Uint8Array;
  identPrivB64: string;
  onProgress: (p: ExportProgress) => void;
}): Promise<RecoveryKitAsset> {
  const { item, crypto, masterKey, identPrivB64, onProgress } = args;

  // Fetch the asset manifest — this rotates the canary on the server,
  // expected.
  const r = await fetch(
    `${API_URL}/vault/${encodeURIComponent(item.asset_id)}`,
    { credentials: "include" },
  );
  if (!r.ok) throw new Error(`fetch ${item.asset_id}: ${r.status}`);
  const manifest = (await r.json()) as ShardedFetchResponse;
  if (manifest.mode !== "sharded") {
    throw new Error(`unexpected mode: ${manifest.mode}`);
  }

  // Unwrap per-asset key. Owner: under master key. Sharee: under the
  // ECDH-derived share wrap key from our own privkey + sender's
  // pubkey. After this step the kit carries the unwrapped key, so the
  // recover tool never has to know about owner-vs-sharee distinctions
  // OR about X25519 at all — it just XChaCha20-decrypts each asset
  // with its own key.
  let perAssetKey: Uint8Array;
  if (!manifest.wrapped_key_b64) {
    perAssetKey = masterKey;
  } else if (manifest.role === "ring_member") {
    if (!manifest.ring_id || !manifest.uploader_pubkey_x25519_b64) {
      throw new Error("ring asset missing ring_id or uploader_pubkey");
    }
    const { ensureRingPrivkey } = await import("./passkey");
    const ringPrivB64 = await ensureRingPrivkey(manifest.ring_id);
    if (!ringPrivB64) throw new Error("could not unwrap ring privkey");
    const wrapB64 = crypto.x25519_recipient_wrap_key(
      ringPrivB64,
      manifest.uploader_pubkey_x25519_b64,
      manifest.asset_id,
    );
    const wrapKey = base64ToBytes(wrapB64);
    const wrappedJson = atob(manifest.wrapped_key_b64);
    perAssetKey = crypto.decrypt_data(wrapKey, wrappedJson);
  } else if (manifest.role === "sharee") {
    if (!manifest.sender_pubkey_x25519_b64) {
      throw new Error("sharee manifest missing sender pubkey");
    }
    const wrapB64 = crypto.x25519_recipient_wrap_key(
      identPrivB64,
      manifest.sender_pubkey_x25519_b64,
      manifest.asset_id,
    );
    const wrapKey = base64ToBytes(wrapB64);
    const wrappedJson = atob(manifest.wrapped_key_b64);
    perAssetKey = crypto.decrypt_data(wrapKey, wrappedJson);
  } else {
    const wrappedJson = atob(manifest.wrapped_key_b64);
    perAssetKey = crypto.decrypt_data(masterKey, wrappedJson);
  }

  // Decrypt the filename hint if present, purely for kit metadata. The
  // recover tool re-derives this from the asset's frame header during
  // reconstruction anyway, so a failure here only affects the display
  // name in the kit summary — not the recovery itself.
  let filename: string | null = null;
  let mime: string | null = null;
  if (manifest.encrypted_meta_b64) {
    try {
      // The encrypted_meta is sealed under the SAME KEK as the
      // per-asset key — master for owners, share wrap key for sharees.
      let metaKey: Uint8Array;
      if (manifest.role === "ring_member" && manifest.ring_id && manifest.uploader_pubkey_x25519_b64) {
        const { ensureRingPrivkey } = await import("./passkey");
        const ringPrivB64 = await ensureRingPrivkey(manifest.ring_id);
        if (ringPrivB64) {
          const wrapB64 = crypto.x25519_recipient_wrap_key(
            ringPrivB64,
            manifest.uploader_pubkey_x25519_b64,
            manifest.asset_id,
          );
          metaKey = base64ToBytes(wrapB64);
        } else {
          metaKey = masterKey; // fallback — likely fails, caught below
        }
      } else if (manifest.role === "sharee" && manifest.sender_pubkey_x25519_b64) {
        const wrapB64 = crypto.x25519_recipient_wrap_key(
          identPrivB64,
          manifest.sender_pubkey_x25519_b64,
          manifest.asset_id,
        );
        metaKey = base64ToBytes(wrapB64);
      } else {
        metaKey = masterKey;
      }
      const metaJson = atob(manifest.encrypted_meta_b64);
      const metaBytes = crypto.decrypt_data(metaKey, metaJson);
      const parsed = JSON.parse(new TextDecoder().decode(metaBytes));
      if (parsed && typeof parsed === "object") {
        filename = typeof parsed.name === "string" ? parsed.name : null;
        mime = typeof parsed.mime === "string" ? parsed.mime : null;
      }
    } catch (e) {
      console.warn(`meta decrypt failed for ${item.asset_id}:`, e);
    }
  }

  // Pull every shard. Each comes down from S3 via the presigned GET
  // URL the server minted for us in the manifest response.
  const total = manifest.shards.length;
  const shards: Array<{ index: number; ciphertext_b64: string | null }> = [];
  for (let i = 0; i < manifest.shards.length; i++) {
    const slot = manifest.shards[i];
    onProgress({
      phase: "shard",
      current: i + 1,
      total,
      label: `${item.asset_id} shard ${i + 1}/${total}`,
    });
    if (!slot.download_url) {
      shards.push({ index: slot.index, ciphertext_b64: null });
      continue;
    }
    try {
      const resp = await fetch(slot.download_url);
      if (!resp.ok) throw new Error(`shard ${i}: ${resp.status}`);
      const bytes = new Uint8Array(await resp.arrayBuffer());
      shards.push({ index: slot.index, ciphertext_b64: bytesToBase64(bytes) });
    } catch (e) {
      console.warn(`shard ${i} fetch failed for ${item.asset_id}:`, e);
      shards.push({ index: slot.index, ciphertext_b64: null });
    }
  }

  return {
    asset_id: manifest.asset_id,
    role: manifest.role === "ring_member"
      ? "ring_member"
      : manifest.role === "sharee"
        ? "sharee"
        : "owner",
    filename,
    mime,
    shared_by_email: item.shared_by_email ?? undefined,
    created_at: item.created_at,
    crypto: {
      aead: "xchacha20-poly1305",
      per_asset_key_b64: bytesToBase64(perAssetKey),
      frame_format: "resqd-frame-v1",
    },
    erasure: {
      k: manifest.data_shards,
      n: manifest.data_shards + manifest.parity_shards,
      original_len: manifest.original_len,
    },
    shards,
  };
}
