"use client";

import { Suspense, useCallback, useEffect, useRef, useState } from "react";
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
  // Streaming-mode assets pause here after the manifest has been
  // decrypted but before any shards are fetched. We need a user
  // gesture to call `showSaveFilePicker` (File System Access API),
  // so the download waits until the user clicks "Save to disk."
  // The streaming context is carried via a ref, not state, to
  // avoid serializing WASM handles and large byte buffers through
  // React state. See `streamingCtxRef`.
  | {
      phase: "metadata-ready";
      name: string | null;
      mime: string | null;
      size: number;
      totalGroups: number;
    }
  // Per-group progress during range-based streaming download.
  // `current` counts groups processed (0-indexed during fetch,
  // last group when complete). `bytesWritten` tracks plaintext
  // bytes delivered to the sink.
  | {
      phase: "streaming-group";
      current: number;
      total: number;
      bytesWritten: number;
      sinkKind: "fsa" | "memory";
    }
  | {
      phase: "done";
      bytes: Uint8Array;
      name: string | null;
      mime: string | null;
      sequence: string | null;
      canaryHash: string | null;
    }
  // Streamed directly to disk via File System Access API. No
  // plaintext in memory — just confirmation + metadata. Distinct
  // phase from `done` so the UI can skip the in-memory preview and
  // Blob download button.
  | {
      phase: "done-streamed";
      name: string | null;
      mime: string | null;
      size: number;
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

/**
 * Minimal WASM streaming decoder/decryptor types the fetch page
 * uses. These live on the same module the positive fetch path
 * already casts through, so we re-declare them here to keep the
 * range-based download self-contained.
 */
interface WasmStreamDecoder {
  decodeGroup: (shardsJson: string) => Uint8Array;
  finish: () => void;
}
interface WasmStreamDecryptor {
  openChunk: (sealedJson: string) => Uint8Array;
  finish: () => void;
}

/**
 * Everything `streamDownload()` needs to pick up where the manifest
 * fetch left off. Held in a `useRef` (not state) because some of
 * these fields are WASM handles or large byte buffers that don't
 * belong in the React render graph, and because we need synchronous
 * access when the user clicks "Save to disk" — the handler must
 * call `showSaveFilePicker` before hitting its first `await` to
 * preserve user activation.
 */
interface StreamingContext {
  manifest: ShardedFetchResponse;
  decoder: WasmStreamDecoder;
  decryptor: WasmStreamDecryptor;
  groups: { data_len: number; shard_size: number; input_hash: number[] }[];
  sequence: string | null;
  canaryHash: string | null;
  name: string | null;
  mime: string | null;
}

/**
 * Fetch a half-open byte range `[start, end)` from a presigned
 * S3 URL. Returns the raw bytes. S3 returns `206 Partial Content`
 * on success; we accept `200` too because a whole-object GET is a
 * valid fallback if the server ignores the Range header for any
 * reason.
 *
 * AWS signs presigned URLs based on the canonical resource and
 * method — NOT the Range header — so adding a Range header to a
 * signed GET is always valid. The signature survives.
 */
async function rangeGetShard(
  downloadUrl: string,
  start: number,
  end: number,
): Promise<Uint8Array> {
  const resp = await fetch(downloadUrl, {
    headers: { Range: `bytes=${start}-${end - 1}` },
  });
  if (!resp.ok && resp.status !== 206) {
    throw new Error(`range GET ${start}-${end - 1} -> ${resp.status}`);
  }
  return new Uint8Array(await resp.arrayBuffer());
}

/** Feature-detect File System Access API (Chrome, Edge, Opera).
 *  Returns false in Firefox + Safari as of 2026-04.
 *
 *  Also honors a `window.__resqdForceMemorySink` test escape hatch
 *  so headless Chromium — where `showSaveFilePicker` exists but has
 *  no UI to display the picker — can exercise the in-memory
 *  fallback path deterministically. Setting the flag in a Playwright
 *  `addInitScript` forces the memory path without affecting
 *  production users. */
function hasFsaApi(): boolean {
  if (typeof window === "undefined") return false;
  if (
    (window as unknown as { __resqdForceMemorySink?: boolean })
      .__resqdForceMemorySink
  ) {
    return false;
  }
  return (
    typeof (window as unknown as { showSaveFilePicker?: unknown })
      .showSaveFilePicker === "function"
  );
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

  // Streaming download context. Populated by `fetchAndDecrypt()`
  // for sharded-stream assets after the manifest is decrypted;
  // consumed by `streamDownload()` when the user clicks "Save to
  // disk." Using a ref instead of state keeps WASM handles out of
  // React's render graph.
  const streamingCtxRef = useRef<StreamingContext | null>(null);

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

          // Build the WASM decoder + decryptor once, up front, so
          // the user-gesture path in `streamDownload()` can go
          // straight into per-group range fetches without any
          // async construction in the critical showSaveFilePicker
          // window. These objects own internal WASM state — pass
          // them through the ref, not React state.
          const wasm = crypto as unknown as {
            WasmStreamDecoder: new (manifestJson: string) => WasmStreamDecoder;
            WasmStreamDecryptor: new (
              key: Uint8Array,
              headerJson: string,
            ) => WasmStreamDecryptor;
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
          const decryptor = new wasm.WasmStreamDecryptor(
            assetKey,
            headerForWasm,
          );

          const groups = manifest.stream_info.stream_manifest.groups;

          // Stash everything `streamDownload()` will need and
          // hand control back to the UI. The user must click
          // "Save to disk" or "Download to memory" to proceed —
          // this is a deliberate pause so the eventual
          // `showSaveFilePicker` call lands in a user-activation
          // context (Chrome refuses to open a Save As dialog
          // without one).
          streamingCtxRef.current = {
            manifest,
            decoder,
            decryptor,
            groups,
            sequence,
            canaryHash,
            name,
            mime,
          };
          setState({
            phase: "metadata-ready",
            name,
            mime,
            size: manifest.original_len,
            totalGroups: groups.length,
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

  /**
   * Range-based streaming download for sharded-stream assets.
   *
   * Call site must be a user gesture (click handler) — the first
   * `await` in this function is `handle.createWritable()`, which
   * only gets user activation if the preceding
   * `window.showSaveFilePicker()` call is synchronous with the
   * click. If you add more work before the picker call, Chrome
   * will reject the picker with `NotAllowedError: Must be
   * handling a user gesture`. Watch for that if you refactor.
   *
   * Peak memory during this path is bounded to one group × 6
   * shards in raw shard bytes, plus the single plaintext chunk
   * being written, plus whatever buffering the File System
   * Access writable does internally. For a typical 64 KB chunk
   * size and 6-way RS, that's well under 100 MB regardless of
   * the total file size.
   *
   * Falls back to in-memory accumulation + Blob download when
   * the File System Access API is unavailable (Firefox, Safari
   * as of 2026-04). The fallback path still benefits from
   * range-based fetches because each group's raw shard bytes are
   * discarded after decoding, capping shard-side peak memory.
   * The plaintext accumulator still grows to the full file size,
   * which matches current fetch behavior.
   */
  const streamDownload = useCallback(async () => {
    const ctx = streamingCtxRef.current;
    if (!ctx) {
      setState({
        phase: "error",
        message: "streaming context missing — reload the page and try again",
      });
      return;
    }

    // Critical: call `showSaveFilePicker` synchronously from the
    // click handler before any await, so user activation survives.
    let writable:
      | {
          write: (data: Uint8Array) => Promise<void>;
          close: () => Promise<void>;
          abort: () => Promise<void>;
        }
      | null = null;
    let sinkKind: "fsa" | "memory" = "memory";

    if (hasFsaApi()) {
      try {
        const picker = (
          window as unknown as {
            showSaveFilePicker: (opts: {
              suggestedName?: string;
              types?: unknown;
            }) => Promise<{
              createWritable: () => Promise<{
                write: (data: Uint8Array) => Promise<void>;
                close: () => Promise<void>;
                abort: () => Promise<void>;
              }>;
            }>;
          }
        ).showSaveFilePicker;
        const handle = await picker({
          suggestedName:
            ctx.name || `resqd-${assetId.slice(0, 8)}.bin`,
        });
        writable = await handle.createWritable();
        sinkKind = "fsa";
      } catch (err) {
        // User cancelled the Save As dialog → transition back to
        // metadata-ready so they can retry without losing the
        // decrypted metadata.
        if (err instanceof DOMException && err.name === "AbortError") {
          setState({
            phase: "metadata-ready",
            name: ctx.name,
            mime: ctx.mime,
            size: ctx.manifest.original_len,
            totalGroups: ctx.groups.length,
          });
          return;
        }
        // Other picker errors (e.g. SecurityError because we lost
        // user activation) fall through to the memory path so the
        // download still works.
        console.warn("showSaveFilePicker unavailable, using memory sink:", err);
      }
    }

    try {
      const plaintextChunks: Uint8Array[] = sinkKind === "memory" ? [] : [];
      let bytesWritten = 0;
      let offset = 0;

      setState({
        phase: "streaming-group",
        current: 0,
        total: ctx.groups.length,
        bytesWritten: 0,
        sinkKind,
      });

      for (let g = 0; g < ctx.groups.length; g++) {
        const gSize = ctx.groups[g].shard_size;
        const isLast = g === ctx.groups.length - 1;
        const rangeStart = offset;
        const rangeEnd = offset + gSize;

        // Fetch this group's slice from each shard in parallel.
        // A failure on up to `parity_shards` shards is tolerable
        // because Reed-Solomon can reconstruct from any 4 of 6
        // — we pass nulls for missing slices and the WASM
        // decoder handles the gaps.
        const shardSlices: (Uint8Array | null)[] = await Promise.all(
          ctx.manifest.shards.map(async (slot) => {
            if (!slot.download_url) return null;
            try {
              return await rangeGetShard(
                slot.download_url,
                rangeStart,
                rangeEnd,
              );
            } catch (e) {
              console.warn(
                `shard ${slot.index} group ${g} range fetch failed:`,
                e,
              );
              return null;
            }
          }),
        );

        const present = shardSlices.filter((s) => s !== null).length;
        if (present < ctx.manifest.data_shards) {
          throw new Error(
            `group ${g}: only ${present}/${ctx.manifest.data_shards} shards available`,
          );
        }

        const sliceJson: (string | null)[] = shardSlices.map((s) =>
          s ? bytesToBase64(s) : null,
        );
        const ciphertext = ctx.decoder.decodeGroup(JSON.stringify(sliceJson));
        const sealedJson = JSON.stringify({
          counter: g,
          is_last: isLast,
          ciphertext_b64: bytesToBase64(new Uint8Array(ciphertext)),
        });
        const plaintextChunk = new Uint8Array(
          ctx.decryptor.openChunk(sealedJson),
        );

        if (sinkKind === "fsa" && writable) {
          await writable.write(plaintextChunk);
        } else {
          plaintextChunks.push(plaintextChunk);
        }
        bytesWritten += plaintextChunk.length;
        offset += gSize;

        setState({
          phase: "streaming-group",
          current: g + 1,
          total: ctx.groups.length,
          bytesWritten,
          sinkKind,
        });
      }

      ctx.decryptor.finish();
      ctx.decoder.finish();

      if (sinkKind === "fsa" && writable) {
        await writable.close();
        setState({
          phase: "done-streamed",
          name: ctx.name,
          mime: ctx.mime,
          size: bytesWritten,
          sequence: ctx.sequence,
          canaryHash: ctx.canaryHash,
        });
      } else {
        // In-memory assembly for browsers without File System
        // Access API. Behavior matches the pre-range code path
        // as far as the user can see — one Blob at the end,
        // click Download — but shard memory is now bounded to
        // the last group.
        const plainFull = new Uint8Array(bytesWritten);
        let writeOff = 0;
        for (const chunk of plaintextChunks) {
          plainFull.set(chunk, writeOff);
          writeOff += chunk.length;
        }
        setState({
          phase: "done",
          bytes: plainFull,
          name: ctx.name,
          mime: ctx.mime,
          sequence: ctx.sequence,
          canaryHash: ctx.canaryHash,
        });
      }
    } catch (err) {
      // Best-effort abort the writable so we don't leave a
      // half-written file on disk when the download errors out.
      if (writable) {
        try {
          await writable.abort();
        } catch {
          // Swallow — we're already in the error path.
        }
      }
      setState({
        phase: "error",
        message: err instanceof Error ? err.message : String(err),
      });
    }
  }, [assetId]);

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
        {state.phase === "metadata-ready" && (
          <div className="space-y-3 text-sm">
            <p className="text-green-400">
              ✓ metadata decrypted — ready to stream
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
              size:{" "}
              <span className="font-mono text-amber-300">
                {state.size.toLocaleString()}
              </span>{" "}
              bytes in {state.totalGroups} group
              {state.totalGroups === 1 ? "" : "s"}
            </p>
            <p className="text-xs text-slate-500 leading-relaxed">
              Large files stream to disk group by group so your browser
              tab never holds the whole file in memory at once.
              {hasFsaApi()
                ? " Click below to pick a save location."
                : " This browser doesn't support streaming to disk — the file will be assembled in memory and offered as a download at the end."}
            </p>
            <button
              onClick={streamDownload}
              className="rounded-lg bg-amber-500 text-slate-900 font-semibold px-5 py-2 text-sm"
            >
              {hasFsaApi() ? "Save to disk…" : "Download to memory"}
            </button>
          </div>
        )}
        {state.phase === "streaming-group" && (
          <div className="space-y-2 text-sm">
            <p className="text-slate-400">
              {state.sinkKind === "fsa"
                ? "Streaming to disk"
                : "Assembling in memory"}{" "}
              — group {state.current}/{state.total}
            </p>
            <div className="h-1 bg-slate-800 rounded overflow-hidden">
              <div
                className="h-full bg-amber-500 transition-all"
                style={{
                  width: `${Math.round(
                    (state.current / Math.max(1, state.total)) * 100,
                  )}%`,
                }}
              />
            </div>
            <p className="text-xs text-slate-500 font-mono">
              {state.bytesWritten.toLocaleString()} bytes written
            </p>
          </div>
        )}
        {state.phase === "done-streamed" && (
          <div className="space-y-3 text-sm">
            <p className="text-green-400">
              ✓ streamed {state.size.toLocaleString()} bytes to disk
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
              <span className="font-mono text-amber-300">
                {state.sequence}
              </span>
            </p>
          </div>
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
