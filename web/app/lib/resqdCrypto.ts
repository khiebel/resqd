/**
 * Client-side crypto bridge to the resqd-core WASM module.
 *
 * Loads the WASM glue lazily from /public/resqd-wasm/ so it never runs
 * during SSR and never ends up in the initial bundle. The user's plaintext
 * and encryption key never leave the browser.
 */

let wasmReady: Promise<WasmApi> | null = null;

interface WasmApi {
  generate_random_key: () => Uint8Array;
  generate_salt: () => Uint8Array;
  derive_key: (passphrase: string, salt: Uint8Array) => Uint8Array;
  encrypt_data: (key: Uint8Array, plaintext: Uint8Array) => string;
  decrypt_data: (key: Uint8Array, blobJson: string) => Uint8Array;
  hash_bytes: (data: Uint8Array) => string;
  /** Erasure-code data into 4+2 Reed-Solomon shards. Returns JSON string. */
  erasure_encode: (data: Uint8Array) => string;
  /** Reconstruct original bytes from shards (JSON array of base64|null). */
  erasure_reconstruct: (shards_json: string, original_len: number) => Uint8Array;
  /**
   * Generate a fresh long-term X25519 identity keypair. Returns a JSON
   * string of shape `{"public_b64": "...", "private_b64": "..."}` —
   * both halves are raw 32-byte scalars encoded as standard base64.
   * The caller is responsible for sealing the private half under the
   * master key before sending it to the server.
   */
  x25519_generate_identity: () => string;
  /** Re-derive the X25519 public half from a private scalar (base64). */
  x25519_public_from_private: (private_b64: string) => string;
  /**
   * Sender side: derive the 32-byte wrap key used to seal the per-asset
   * key for a specific recipient, with per-asset domain separation via
   * HKDF-SHA256 over the X25519 shared secret. Returns base64.
   */
  x25519_sender_wrap_key: (
    sender_private_b64: string,
    recipient_public_b64: string,
    asset_id: string,
  ) => string;
  /** Recipient side: mirror of `x25519_sender_wrap_key`. */
  x25519_recipient_wrap_key: (
    recipient_private_b64: string,
    sender_public_b64: string,
    asset_id: string,
  ) => string;
}

/** Shape of the JSON string returned by `erasure_encode`. */
export interface ErasureEncoded {
  shards: string[]; // base64
  original_len: number;
  data_shards: number;
  parity_shards: number;
}

export async function getCrypto(): Promise<WasmApi> {
  if (typeof window === "undefined") {
    throw new Error("resqd crypto only runs in the browser");
  }
  if (!wasmReady) {
    wasmReady = (async () => {
      // The wasm-bindgen glue is in public/ so it's served as a static file.
      // Dynamic import via a runtime-built URL keeps Next's bundler from
      // trying to resolve it at build time.
      // Cache-bust: the WASM glue JS has a static filename (no content
      // hash) so CF Pages edge cache serves stale copies after deploys.
      // Append a build-time version tag so a redeploy forces a fresh fetch.
      const v = "20260405";
      const glueUrl = `/resqd-wasm/resqd_core.js?v=${v}`;
      const mod = await import(/* webpackIgnore: true */ glueUrl);
      await mod.default({ module_or_path: `/resqd-wasm/resqd_core_bg.wasm?v=${v}` });
      return mod as WasmApi;
    })();
  }
  return wasmReady;
}

/**
 * Convert a Uint8Array to a lowercase hex string (for displaying keys to
 * the user so they can copy/save them).
 */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Parse a hex string back into a Uint8Array. Tolerant of whitespace and
 * optional `0x` prefix. Throws on invalid input.
 */
export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.trim().replace(/^0x/i, "").replace(/\s+/g, "");
  if (clean.length % 2 !== 0) throw new Error("odd-length hex");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) throw new Error(`invalid hex at offset ${i * 2}`);
    out[i] = byte;
  }
  return out;
}

/**
 * Convert a base64 string to a Uint8Array (for shard uploads).
 */
export function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

/**
 * Convert a Uint8Array to base64.
 */
export function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

/**
 * The API endpoint to talk to. All traffic flows through the
 * resqd-api-proxy Worker on api.resqd.ai, which injects the origin
 * secret and forwards to the Lambda. Override with NEXT_PUBLIC_RESQD_API
 * for local dev against a cargo-lambda watch server.
 */
export const API_URL =
  process.env.NEXT_PUBLIC_RESQD_API || "https://api.resqd.ai";
