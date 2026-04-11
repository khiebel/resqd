"use client";

import { Suspense, useCallback, useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import Link from "next/link";
import {
  getCrypto,
  bytesToBase64,
  base64ToBytes,
  API_URL,
} from "../lib/resqdCrypto";
import {
  loadMasterKey,
  fetchMe,
  loadX25519Identity,
  ensureRingPrivkey,
} from "../lib/passkey";

type FetchState =
  | { phase: "idle" }
  | { phase: "requesting" }
  | { phase: "downloading-shards"; done: number; total: number }
  | { phase: "reconstructing" }
  | { phase: "decrypting" }
  | {
      phase: "done";
      bytes: Uint8Array;
      name: string | null;
      mime: string | null;
      sequence: string | null;
      canaryHash: string | null;
    }
  | { phase: "error"; message: string };

interface ShardedFetchResponse {
  /** `"sharded"` for legacy single-shot; `"sharded-stream"` for Track 1 uploads. */
  mode: "sharded" | "sharded-stream";
  asset_id: string;
  original_len: number;
  data_shards: number;
  parity_shards: number;
  shards: { index: number; download_url: string | null }[];
  /**
   * Streaming uploads only. The inner shape mirrors the Rust
   * `StreamInfo` — we treat it as opaque and forward `stream_manifest`
   * + `stream_header` to the WASM decoders verbatim.
   */
  stream_info?: {
    version: number;
    stream_manifest: {
      version: number;
      data_shards: number;
      parity_shards: number;
      total_input_bytes: number;
      groups: Array<{ data_len: number; shard_size: number; input_hash: number[] }>;
    };
    stream_header: { stream_id: number[]; chunk_size: number };
  };
  canary_sequence: number;
  canary_hash_hex: string;
  ttl_seconds: number;
  /**
   * Role in which the caller is reading this asset. `"owner"` means
   * the wrapped key is sealed under the caller's master key; `"sharee"`
   * means it's sealed under the ECDH-derived share wrap key and
   * `sender_pubkey_x25519_b64` will be present.
   */
  role?: "owner" | "sharee" | "ring_member";
  /** Per-asset key — wrapping depends on `role`. */
  wrapped_key_b64?: string;
  /** Filename + mime encrypted under the same key that wraps per-asset key. */
  encrypted_meta_b64?: string;
  /** For sharee fetches only. */
  sender_pubkey_x25519_b64?: string;
  /** Ring asset fields. */
  ring_id?: string;
  uploader_pubkey_x25519_b64?: string;
}

/** Unwrap the {v:1, name, mime} plaintext frame the upload page writes. */
function unwrapFrame(plaintext: Uint8Array): {
  body: Uint8Array;
  name: string | null;
  mime: string | null;
} {
  const legacy = { body: plaintext, name: null, mime: null };
  if (plaintext.length < 4) return legacy;
  const headerLen = new DataView(
    plaintext.buffer,
    plaintext.byteOffset,
    4,
  ).getUint32(0, true);
  if (headerLen === 0 || headerLen > 1024 || 4 + headerLen > plaintext.length) {
    return legacy;
  }
  try {
    const headerJson = new TextDecoder("utf-8", { fatal: true }).decode(
      plaintext.subarray(4, 4 + headerLen),
    );
    const header = JSON.parse(headerJson);
    if (!header || typeof header !== "object" || header.v !== 1) return legacy;
    return {
      body: plaintext.subarray(4 + headerLen),
      name: typeof header.name === "string" ? header.name : null,
      mime: typeof header.mime === "string" ? header.mime : null,
    };
  } catch {
    return legacy;
  }
}

function FetchInner() {
  const params = useSearchParams();
  const [assetId, setAssetId] = useState(params.get("id") || "");
  const [state, setState] = useState<FetchState>({ phase: "idle" });

  useEffect(() => {
    (async () => {
      const me = await fetchMe();
      if (!me || !loadMasterKey()) {
        window.location.href = "/login/";
        return;
      }
      if (params.get("id")) {
        fetchAndDecrypt();
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const fetchAndDecrypt = useCallback(async () => {
    try {
      if (!assetId) {
        setState({ phase: "error", message: "asset id required" });
        return;
      }
      const masterKey = loadMasterKey();
      if (!masterKey) {
        window.location.href = "/login/";
        return;
      }

      setState({ phase: "requesting" });
      const metaResp = await fetch(
        `${API_URL}/vault/${encodeURIComponent(assetId)}`,
        { credentials: "include" },
      );
      if (!metaResp.ok) {
        throw new Error(`api ${metaResp.status}: ${await metaResp.text()}`);
      }
      const sequence = metaResp.headers.get("x-resqd-canary-sequence");
      const canaryHash = metaResp.headers.get("x-resqd-canary-hash");
      const contentType = metaResp.headers.get("content-type") || "";

      let plaintextBytes: Uint8Array;

      if (contentType.includes("application/json")) {
        const manifest: ShardedFetchResponse = await metaResp.json();
        if (manifest.mode !== "sharded" && manifest.mode !== "sharded-stream") {
          throw new Error(`unexpected mode: ${manifest.mode}`);
        }

        // ───────── UNWRAP PER-ASSET KEY ─────────
        //
        // Three cases:
        //
        // 1. Legacy asset (no wrapped key, owner role implicit) — the
        //    master key IS the direct decryption key. Pre-auth upload.
        //
        // 2. Owner fetch (role === "owner" or unset, wrapped_key_b64
        //    present) — the wrapped key is sealed under the caller's
        //    master key. Standard unwrap.
        //
        // 3. Sharee fetch (role === "sharee") — the wrapped key is
        //    sealed under the ECDH-derived share wrap key, NOT the
        //    master key. Recompute that wrap key from our own X25519
        //    privkey + the sender's pubkey, mix the asset_id into the
        //    HKDF info for per-asset domain separation.
        const crypto = await getCrypto();
        let assetKey: Uint8Array;
        // `metaKey` is whatever unwrapped the per-asset key — master
        // key for owners, ECDH wrap key for sharees and ring members.
        // The streaming path uses it to decrypt `encrypted_meta_b64`
        // for the filename; the single-shot path doesn't need it
        // because the filename is framed inside the plaintext body.
        let metaKey: Uint8Array = masterKey;
        if (!manifest.wrapped_key_b64) {
          assetKey = masterKey;
        } else if (manifest.role === "ring_member") {
          // Ring asset: unwrap per-asset key using ring privkey +
          // uploader's pubkey via ECDH.
          if (!manifest.ring_id || !manifest.uploader_pubkey_x25519_b64) {
            throw new Error("ring asset missing ring_id or uploader_pubkey");
          }
          const ringPrivB64 = await ensureRingPrivkey(manifest.ring_id);
          if (!ringPrivB64) {
            throw new Error(
              "could not unwrap ring privkey — log out and back in, or check ring membership",
            );
          }
          const wrapKeyB64 = crypto.x25519_recipient_wrap_key(
            ringPrivB64,
            manifest.uploader_pubkey_x25519_b64,
            manifest.asset_id,
          );
          const wrapKey = base64ToBytes(wrapKeyB64);
          const wrappedJson = atob(manifest.wrapped_key_b64);
          assetKey = crypto.decrypt_data(wrapKey, wrappedJson);
          metaKey = wrapKey;
        } else if (manifest.role === "sharee") {
          if (!manifest.sender_pubkey_x25519_b64) {
            throw new Error("sharee fetch missing sender_pubkey_x25519_b64");
          }
          const ident = loadX25519Identity();
          if (!ident) {
            throw new Error(
              "X25519 identity not loaded — log out and back in to establish one",
            );
          }
          const wrapKeyB64 = crypto.x25519_recipient_wrap_key(
            ident.privB64,
            manifest.sender_pubkey_x25519_b64,
            manifest.asset_id,
          );
          const wrapKey = base64ToBytes(wrapKeyB64);
          const wrappedJson = atob(manifest.wrapped_key_b64);
          assetKey = crypto.decrypt_data(wrapKey, wrappedJson);
          metaKey = wrapKey;
        } else {
          const wrappedJson = atob(manifest.wrapped_key_b64);
          assetKey = crypto.decrypt_data(masterKey, wrappedJson);
          metaKey = masterKey;
        }

        // ───────── STREAMING DOWNLOAD PATH ─────────
        //
        // For sharded-stream uploads we can't use the single-shot
        // erasure_reconstruct + decrypt_data pair — the ciphertext
        // format is per-chunk SealedChunks, not a single
        // whole-file XChaCha20 blob. Instead we:
        //
        //   1. Download every shard fully (no range requests — MVP).
        //   2. For each group in the stream manifest, slice the
        //      corresponding bytes from each shard.
        //   3. Hand the 6 slices to `WasmStreamDecoder.decodeGroup`
        //      (Reed-Solomon reconstruct → per-chunk ciphertext).
        //   4. Wrap that ciphertext in a `SealedChunk` JSON shape
        //      (counter = group index, is_last = last group).
        //   5. Hand the JSON to `WasmStreamDecryptor.openChunk` to
        //      recover the plaintext bytes for that chunk.
        //   6. Concatenate plaintext group-by-group into the output.
        //   7. Call `decryptor.finish()` to assert the last chunk
        //      was marked `is_last` — truncation detection.
        //
        // Filename/mime come from `encrypted_meta_b64` decrypted with
        // `metaKey` (NOT the asset key — same key that unwraps the
        // per-asset key).
        if (manifest.mode === "sharded-stream") {
          if (!manifest.stream_info) {
            throw new Error("sharded-stream response missing stream_info");
          }
          if (!manifest.encrypted_meta_b64) {
            throw new Error("sharded-stream response missing encrypted_meta_b64");
          }

          // Decrypt filename/mime.
          const metaPlaintext = crypto.decrypt_data(
            metaKey,
            atob(manifest.encrypted_meta_b64),
          );
          const metaJson = JSON.parse(new TextDecoder().decode(metaPlaintext));
          const name: string | null =
            typeof metaJson.name === "string" ? metaJson.name : null;
          const mime: string | null =
            typeof metaJson.mime === "string" ? metaJson.mime : null;

          // Download all six shards in parallel. The MVP holds them
          // all in memory; a future pass can switch to per-group
          // range requests to bound memory for multi-GB files.
          const total = manifest.shards.length;
          let done = 0;
          setState({ phase: "downloading-shards", done, total });
          const shardBytes: (Uint8Array | null)[] = await Promise.all(
            manifest.shards.map(async (slot) => {
              if (!slot.download_url) return null;
              try {
                const r = await fetch(slot.download_url);
                if (!r.ok) throw new Error(`${r.status}`);
                const bytes = new Uint8Array(await r.arrayBuffer());
                done += 1;
                setState({ phase: "downloading-shards", done, total });
                return bytes;
              } catch (e) {
                console.warn(`shard ${slot.index} failed:`, e);
                return null;
              }
            }),
          );
          const presentCount = shardBytes.filter((s) => s !== null).length;
          if (presentCount < manifest.data_shards) {
            throw new Error(
              `only ${presentCount}/${manifest.data_shards} required shards available`,
            );
          }

          setState({ phase: "reconstructing" });
          // The WASM streaming decoder + decryptor constructors take
          // JSON strings that serde emits for StreamManifest and
          // StreamHeader — we received them verbatim in
          // `manifest.stream_info`. The existing `getCrypto()` helper
          // already loaded the WASM module; the streaming classes
          // hang off the same module exports, so cast through
          // `unknown` to get them.
          const wasm = crypto as unknown as {
            WasmStreamDecoder: new (manifestJson: string) => {
              decodeGroup: (shardsJson: string) => Uint8Array;
              finish: () => void;
            };
            WasmStreamDecryptor: new (
              key: Uint8Array,
              headerJson: string,
            ) => {
              openChunk: (sealedJson: string) => Uint8Array;
              finish: () => void;
            };
          };
          const decoder = new wasm.WasmStreamDecoder(
            JSON.stringify(manifest.stream_info.stream_manifest),
          );
          // The Rust backend serializes `stream_id` as an array of 20
          // numbers; the WASM `WasmStreamDecryptor` constructor
          // expects a JSON object with `stream_id_b64` (base64) +
          // `chunk_size`. Translate between the two shapes here.
          const sid = manifest.stream_info.stream_header.stream_id;
          const sidBytes = new Uint8Array(sid);
          const headerForWasm = JSON.stringify({
            stream_id_b64: bytesToBase64(sidBytes),
            chunk_size: manifest.stream_info.stream_header.chunk_size,
          });
          const decryptor = new wasm.WasmStreamDecryptor(assetKey, headerForWasm);

          // Iterate groups in order. Each group's shard slice is
          // `shard_size` bytes long at `offset` = sum of prior groups'
          // shard sizes. The erasure decoder accepts a JSON array of
          // 6 base64 strings (or nulls for missing shards) — we
          // convert here.
          const groups = manifest.stream_info.stream_manifest.groups;
          const plaintextChunks: Uint8Array[] = [];
          let totalPlaintextLen = 0;
          let offset = 0;
          for (let g = 0; g < groups.length; g++) {
            const gSize = groups[g].shard_size;
            const isLast = g === groups.length - 1;
            const slice: (string | null)[] = shardBytes.map((s) => {
              if (!s) return null;
              return bytesToBase64(s.subarray(offset, offset + gSize));
            });
            offset += gSize;

            const ciphertext = decoder.decodeGroup(JSON.stringify(slice));
            const sealedJson = JSON.stringify({
              counter: g,
              is_last: isLast,
              ciphertext_b64: bytesToBase64(new Uint8Array(ciphertext)),
            });
            const plaintextChunk = decryptor.openChunk(sealedJson);
            plaintextChunks.push(new Uint8Array(plaintextChunk));
            totalPlaintextLen += plaintextChunk.length;
          }
          decryptor.finish();

          // Stitch together the per-group plaintext slices.
          const plainFull = new Uint8Array(totalPlaintextLen);
          let writeOff = 0;
          for (const chunk of plaintextChunks) {
            plainFull.set(chunk, writeOff);
            writeOff += chunk.length;
          }

          setState({
            phase: "done",
            bytes: plainFull,
            name,
            mime,
            sequence,
            canaryHash,
          });
          return;
        }

        const total = manifest.shards.length;
        let done = 0;
        setState({ phase: "downloading-shards", done, total });
        const shardResults: (string | null)[] = await Promise.all(
          manifest.shards.map(async (slot) => {
            if (!slot.download_url) return null;
            try {
              const r = await fetch(slot.download_url);
              if (!r.ok) throw new Error(`${r.status}`);
              const bytes = new Uint8Array(await r.arrayBuffer());
              done += 1;
              setState({ phase: "downloading-shards", done, total });
              return bytesToBase64(bytes);
            } catch (e) {
              console.warn(`shard ${slot.index} failed:`, e);
              return null;
            }
          }),
        );

        const present = shardResults.filter((s) => s !== null).length;
        if (present < manifest.data_shards) {
          throw new Error(
            `only ${present}/${manifest.data_shards} required shards available`,
          );
        }

        setState({ phase: "reconstructing" });
        const encryptedBytes = crypto.erasure_reconstruct(
          JSON.stringify(shardResults),
          manifest.original_len,
        );
        const blobJson = new TextDecoder().decode(encryptedBytes);

        setState({ phase: "decrypting" });
        plaintextBytes = crypto.decrypt_data(assetKey, blobJson);
      } else {
        // Legacy inline small-file path.
        const ciphertextJson = await metaResp.text();
        setState({ phase: "decrypting" });
        const crypto = await getCrypto();
        plaintextBytes = crypto.decrypt_data(masterKey, ciphertextJson);
      }

      const { body, name, mime } = unwrapFrame(plaintextBytes);
      setState({
        phase: "done",
        bytes: body,
        name,
        mime,
        sequence,
        canaryHash,
      });
    } catch (e) {
      setState({
        phase: "error",
        message: e instanceof Error ? e.message : String(e),
      });
    }
  }, [assetId]);

  const download = useCallback(() => {
    if (state.phase !== "done") return;
    const blob = new Blob([new Uint8Array(state.bytes)], {
      type: state.mime || "application/octet-stream",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = state.name || `resqd-${assetId.slice(0, 8)}.bin`;
    a.click();
    URL.revokeObjectURL(url);
  }, [state, assetId]);

  const preview =
    state.phase === "done" && state.bytes.length < 4096
      ? new TextDecoder("utf-8", { fatal: false }).decode(state.bytes)
      : null;

  return (
    <main className="mx-auto max-w-2xl px-6 py-12 text-slate-100">
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-3xl font-bold">Fetch from RESQD</h1>
        <Link
          href="/vault/"
          className="text-xs text-amber-400 hover:underline"
        >
          My vault →
        </Link>
      </div>
      <p className="text-sm text-slate-400 mb-8">
        Each fetch rotates the canary and anchors a new commitment on Base
        Sepolia. Shards are downloaded directly from storage and reassembled
        in your browser. Your key never leaves the browser.
      </p>

      <section className="space-y-4 mb-6">
        <div>
          <label className="block text-xs font-medium text-slate-400 uppercase tracking-wide mb-1">
            Asset ID
          </label>
          <input
            type="text"
            value={assetId}
            onChange={(e) => setAssetId(e.target.value)}
            className="w-full bg-slate-900 border border-slate-800 rounded-lg p-2 text-sm font-mono"
          />
        </div>
        <button
          onClick={fetchAndDecrypt}
          disabled={!assetId}
          className="rounded-lg bg-amber-500 text-slate-900 font-medium px-5 py-2 text-sm disabled:opacity-30"
        >
          Fetch & Decrypt
        </button>
      </section>

      <section className="bg-slate-900 border border-slate-800 rounded-xl p-5 min-h-24">
        {state.phase === "idle" && (
          <p className="text-slate-500 text-sm">
            Paste an asset id and click Fetch, or open one from your vault.
          </p>
        )}
        {state.phase === "requesting" && (
          <p className="text-slate-400 text-sm">Requesting shard URLs…</p>
        )}
        {state.phase === "downloading-shards" && (
          <p className="text-slate-400 text-sm">
            Downloading shards in parallel ({state.done}/{state.total})…
          </p>
        )}
        {state.phase === "reconstructing" && (
          <p className="text-slate-400 text-sm">
            Reconstructing via Reed-Solomon in WASM…
          </p>
        )}
        {state.phase === "decrypting" && (
          <p className="text-slate-400 text-sm">Decrypting in browser…</p>
        )}
        {state.phase === "error" && (
          <p className="text-red-400 text-sm">Error: {state.message}</p>
        )}
        {state.phase === "done" && (
          <div className="space-y-3 text-sm">
            <p className="text-green-400">
              ✓ decrypted {state.bytes.length.toLocaleString()} bytes
            </p>
            {state.name && (
              <p className="text-xs text-slate-400">
                filename:{" "}
                <span className="font-mono text-amber-300">{state.name}</span>
                {state.mime && (
                  <span className="text-slate-500"> ({state.mime})</span>
                )}
              </p>
            )}
            <p className="text-xs text-slate-400">
              canary sequence after rotation:{" "}
              <span className="font-mono text-amber-300">{state.sequence}</span>
            </p>
            {preview && (
              <pre className="bg-slate-950 border border-slate-800 rounded p-3 text-xs whitespace-pre-wrap">
                {preview}
              </pre>
            )}
            <button
              onClick={download}
              className="rounded-lg bg-slate-700 hover:bg-slate-600 px-4 py-2 text-xs"
            >
              Download
            </button>
          </div>
        )}
      </section>
    </main>
  );
}

export default function FetchPage() {
  return (
    <Suspense fallback={<div className="p-8 text-slate-400">Loading…</div>}>
      <FetchInner />
    </Suspense>
  );
}
