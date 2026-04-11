/**
 * StreamingUploader — large-file streaming upload to /vault/stream/*.
 *
 * The user-facing single-shot path (`POST /vault/init` → `PUT` shards →
 * `POST /vault/{id}/commit`) runs the whole file through WASM memory at
 * once. That caps practical file sizes at ~200 MB before the browser tab
 * OOMs. This module takes the streaming path added in Chunk 1.4:
 *
 *   1. Read the file in plaintext chunks (default 1 MB).
 *   2. For each chunk: `crypto::stream::StreamEncryptor.sealChunk` →
 *      ciphertext bytes → `erasure::stream::StreamEncoder.encodeGroup`
 *      → 6 shard-chunks.
 *   3. Buffer each shard's bytes until the buffer reaches S3's 5 MB
 *      minimum part size, then flush as a single `PUT` to a presigned
 *      UploadPart URL.
 *   4. When the file ends, flush the trailing (possibly-smaller) final
 *      part of each shard.
 *   5. `POST /vault/stream/{asset_id}/commit` with the full stream
 *      manifest + header + per-shard completed parts.
 *
 * Bytes never flow through the Lambda — the client PUTs directly to S3
 * via presigned URLs. Lambda only sees the init/commit metadata.
 *
 * This file is pure logic; there is no React here. The upload page
 * decides which path to take based on `file.size` and passes a ready-to-
 * use per-asset key + auth state.
 */

import { base64ToBytes, bytesToBase64 } from "./resqdCrypto";
import {
  AdaptiveBandwidthController,
  type BandwidthState,
} from "./adaptiveBandwidth";

// ── Tunables ─────────────────────────────────────────────────────────

/** Bytes of plaintext per encryptor chunk. */
const DEFAULT_CHUNK_SIZE = 1 * 1024 * 1024; // 1 MB

/**
 * Minimum S3 multipart part size. S3 requires every part except the
 * final one to be ≥5 MB. Any buffered bytes below this threshold stay
 * in memory until either more arrive or the stream ends.
 */
const MIN_PART_SIZE = 5 * 1024 * 1024; // 5 MB

/** Presigned URL batch size — traded off against Lambda round-trips. */
const PRESIGN_BATCH = 20;

const TOTAL_SHARDS = 6;

// ── WASM type forwarding ─────────────────────────────────────────────
//
// These shapes mirror the Rust bindings in `core/src/wasm.rs`.
// They're re-declared here (not imported from resqdCrypto.ts) because
// the streaming module is the only consumer — centralizing them in
// resqdCrypto.ts would bloat the hot path for everyone else.

interface WasmStreamEncryptor {
  headerJson(): string;
  sealChunk(plaintext: Uint8Array, isLast: boolean): string;
}

interface WasmStreamEncryptorCtor {
  new (key: Uint8Array, chunkSize: number): WasmStreamEncryptor;
}

interface WasmStreamEncoder {
  encodeGroup(input: Uint8Array): string;
  groupsEncoded(): number;
  totalInputBytes(): string;
  finishJson(): string;
}

interface WasmStreamEncoderCtor {
  new (): WasmStreamEncoder;
}

/**
 * Streaming BLAKE3 hasher. One instance per shard; call `update` every
 * time a shard byte range is appended, then `finalizeHex` once the
 * shard is complete. Produces the hex digest we ship with the commit
 * for Track 2 proof-of-absorption verification.
 */
interface WasmBlake3Hasher {
  update(data: Uint8Array): void;
  finalizeHex(): string;
}

interface WasmBlake3HasherCtor {
  new (): WasmBlake3Hasher;
}

interface WasmStreamingApi {
  WasmStreamEncryptor: WasmStreamEncryptorCtor;
  WasmStreamEncoder: WasmStreamEncoderCtor;
  WasmBlake3Hasher: WasmBlake3HasherCtor;
}

/**
 * Lazy-load the WASM module. Mirrors `getCrypto` in resqdCrypto.ts but
 * returns the streaming bindings. Same instance is reused across calls
 * because wasm-bindgen modules are singletons.
 */
let streamingWasmPromise: Promise<WasmStreamingApi> | null = null;

async function loadStreamingWasm(): Promise<WasmStreamingApi> {
  if (typeof window === "undefined") {
    throw new Error("streaming uploader only runs in the browser");
  }
  if (!streamingWasmPromise) {
    streamingWasmPromise = (async () => {
      const v = "20260411";
      const glueUrl = `/resqd-wasm/resqd_core.js?v=${v}`;
      const mod = await import(/* webpackIgnore: true */ glueUrl);
      await mod.default({ module_or_path: `/resqd-wasm/resqd_core_bg.wasm?v=${v}` });
      return mod as unknown as WasmStreamingApi;
    })();
  }
  return streamingWasmPromise;
}

// ── API shapes (match api/src/stream.rs) ─────────────────────────────

interface StreamInitResponse {
  asset_id: string;
  data_shards: number;
  parity_shards: number;
  shards: Array<{
    shard_index: number;
    upload_id: string;
    s3_key: string;
  }>;
  part_ttl_seconds: number;
}

interface StreamPresignedPartsResponse {
  shard_index: number;
  parts: Array<{
    part_number: number;
    upload_url: string;
  }>;
}

interface StreamCommitResponse {
  asset_id: string;
  total_input_bytes: number;
  group_count: number;
  data_shards: number;
  parity_shards: number;
  canary_sequence: number;
  canary_hash_hex: string;
  anchored_on_chain: boolean;
}

interface CompletedPart {
  part_number: number;
  etag: string;
}

// ── Per-shard upload buffer ──────────────────────────────────────────
//
// Holds bytes for one shard that are destined for S3 multipart parts.
// Uploads a part as soon as the buffered size crosses `MIN_PART_SIZE`,
// reserving presigned URLs in batches of `PRESIGN_BATCH`.

class ShardBuffer {
  /** 1-indexed: the next S3 part number this shard will emit. */
  private nextPartNumber = 1;
  /** Buffered bytes waiting to become a part. */
  private pending: Uint8Array[] = [];
  private pendingLen = 0;
  /** Pre-fetched (part_number → URL) map. Drained as parts flush. */
  private presignedUrls = new Map<number, string>();
  /** Parts successfully uploaded, ready for CompleteMultipartUpload. */
  public completed: CompletedPart[] = [];
  /**
   * Total bytes appended into this shard across the whole stream.
   * Shipped in the commit as `expected_shard_bytes[shardIndex]` — the
   * server HeadObjects the composite shard after
   * CompleteMultipartUpload and rejects commit on mismatch (Chunk 2.2).
   */
  public totalBytes = 0;

  constructor(
    private readonly shardIndex: number,
    private readonly assetId: string,
    private readonly apiUrl: string,
    /**
     * Running BLAKE3 over every byte that flows through this shard.
     * Finalized once at commit time and shipped as
     * `expected_shard_hashes_hex[shardIndex]` — Chunk 2.1 of Track 2.
     */
    private readonly hasher: WasmBlake3Hasher,
    /**
     * Shared across all six ShardBuffers. Every completed S3 part PUT
     * feeds wall-clock + bytes into this controller; the next
     * `flushOnePart` call honors whatever inter-block delay it
     * prescribes. Track 3 Chunks 3.2 + 3.3.
     */
    private readonly bandwidth: AdaptiveBandwidthController,
  ) {}

  /**
   * Append bytes to this shard's buffer. Flushes parts as soon as the
   * buffer crosses `MIN_PART_SIZE`. Also feeds the running BLAKE3
   * hasher so that `expectedHashHex()` returns the full shard digest
   * once the stream is complete.
   */
  async append(bytes: Uint8Array): Promise<void> {
    this.hasher.update(bytes);
    this.totalBytes += bytes.length;
    this.pending.push(bytes);
    this.pendingLen += bytes.length;
    while (this.pendingLen >= MIN_PART_SIZE) {
      await this.flushOnePart(MIN_PART_SIZE);
    }
  }

  /** Finalize the running BLAKE3 to a hex string. Call exactly once. */
  expectedHashHex(): string {
    return this.hasher.finalizeHex();
  }

  /**
   * Flush whatever is still in the buffer as the final (possibly-small)
   * part. Safe to call with an empty buffer — does nothing.
   */
  async flushFinal(): Promise<void> {
    if (this.pendingLen === 0) return;
    await this.flushOnePart(this.pendingLen);
  }

  // Internals --------------------------------------------------------

  private async flushOnePart(targetSize: number): Promise<void> {
    // Honor the adaptive-bandwidth controller's delay BEFORE starting
    // the next transfer. When the home pipe is under pressure (from
    // a video call, game console, etc.) the controller will have
    // prescribed a real delay; in the clear path this is 0 ms and
    // the promise resolves immediately.
    const delay = this.bandwidth.getInterBlockDelayMs();
    if (delay > 0) {
      await new Promise<void>((resolve) => setTimeout(resolve, delay));
    }

    const partBytes = this.takeBytes(targetSize);
    const partNumber = this.nextPartNumber++;
    const url = await this.getPresignedUrl(partNumber);

    const startMs = performance.now();
    const resp = await fetch(url, {
      method: "PUT",
      body: new Blob([new Uint8Array(partBytes)]),
    });
    if (!resp.ok) {
      const text = await resp.text().catch(() => "");
      throw new Error(
        `shard ${this.shardIndex} part ${partNumber} PUT failed: ${resp.status} ${text}`,
      );
    }
    const elapsedMs = performance.now() - startMs;

    // Feed the successful transfer into the adaptive bandwidth
    // controller. It normalizes across varying part sizes, tracks a
    // rolling median, and updates its congestion state — the NEXT
    // call to flushOnePart will see any resulting delay. Track 3.2.
    this.bandwidth.reportBlock(partBytes.length, elapsedMs);

    // ETag is wrapped in double-quotes by S3 — keep the quotes, the
    // server-side CompleteMultipartUpload expects them verbatim.
    const etag = resp.headers.get("ETag");
    if (!etag) {
      throw new Error(
        `shard ${this.shardIndex} part ${partNumber}: S3 response missing ETag header`,
      );
    }
    this.completed.push({ part_number: partNumber, etag });
  }

  /** Pull exactly `n` bytes off the pending queue. */
  private takeBytes(n: number): Uint8Array {
    const out = new Uint8Array(n);
    let written = 0;
    while (written < n) {
      const head = this.pending[0];
      const take = Math.min(head.length, n - written);
      out.set(head.subarray(0, take), written);
      written += take;
      if (take === head.length) {
        this.pending.shift();
      } else {
        this.pending[0] = head.subarray(take);
      }
    }
    this.pendingLen -= n;
    return out;
  }

  /** Ensure we have a presigned URL for `partNumber`, fetching a batch if needed. */
  private async getPresignedUrl(partNumber: number): Promise<string> {
    const cached = this.presignedUrls.get(partNumber);
    if (cached) {
      this.presignedUrls.delete(partNumber);
      return cached;
    }

    // Fetch the next batch starting from this part number. CORS allows
    // credentialed fetch from resqd.ai to api.resqd.ai.
    const nums: number[] = [];
    for (let i = 0; i < PRESIGN_BATCH; i++) nums.push(partNumber + i);

    const resp = await fetch(
      `${this.apiUrl}/vault/stream/${encodeURIComponent(this.assetId)}/presigned-parts`,
      {
        method: "POST",
        credentials: "include",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          shard_index: this.shardIndex,
          part_numbers: nums,
        }),
      },
    );
    if (!resp.ok) {
      throw new Error(
        `presigned-parts shard ${this.shardIndex} failed: ${resp.status} ${await resp.text()}`,
      );
    }
    const data = (await resp.json()) as StreamPresignedPartsResponse;
    for (const p of data.parts) {
      this.presignedUrls.set(p.part_number, p.upload_url);
    }
    const found = this.presignedUrls.get(partNumber);
    if (!found) {
      throw new Error(
        `presigned-parts shard ${this.shardIndex} part ${partNumber}: URL not in response`,
      );
    }
    this.presignedUrls.delete(partNumber);
    return found;
  }
}

// ── Public interface ─────────────────────────────────────────────────

export interface CommitMeta {
  /** Wrapped per-asset key (base64) — sealed under master key or ring recipient. */
  wrappedKeyB64: string;
  /** Encrypted filename + mime metadata (base64). */
  encryptedMetaB64: string;
  /** Uploader X25519 public key (base64) — only set for ring uploads. */
  uploaderPubkeyX25519B64?: string;
}

export interface BandwidthSnapshot {
  state: BandwidthState;
  currentSpeedBps: number;
  overallThroughputBps: number;
  interBlockDelayMs: number;
}

export interface StreamingUploadOptions {
  /** Bytes of plaintext per encryptor chunk. Default 1 MB. */
  chunkSize?: number;
  /** Optional progress callback — called with cumulative plaintext bytes processed. */
  onProgress?: (bytesProcessed: number, totalBytes: number) => void;
  /**
   * Optional adaptive-bandwidth snapshot callback. Fires after every
   * completed part PUT so the UI can surface a "polite mode" badge
   * and live throughput. Track 3 Chunk 3.4.
   */
  onBandwidth?: (snapshot: BandwidthSnapshot) => void;
  /** Ring target for shared uploads. Omit for personal vault. */
  ringId?: string;
  /**
   * Produce the commit metadata. Called once after `/vault/stream/init`
   * returns an `asset_id`. For personal uploads the wrap is
   * asset-id-independent so a closure can ignore the argument; for
   * ring uploads the wrap binds `asset_id` via HKDF so the callback
   * must use it. Runs before any S3 bytes move, so a failure here
   * triggers a clean abort.
   */
  prepareCommitMeta: (assetId: string) => Promise<CommitMeta> | CommitMeta;
}

/**
 * Upload `file` as an encrypted+erasure-coded stream. Returns the
 * commit response from `/vault/stream/{id}/commit`.
 *
 * The caller is responsible for:
 *   - Generating the 32-byte per-asset symmetric key.
 *   - Providing `prepareCommitMeta(assetId)` that wraps the per-asset
 *     key (under master key or ring recipient) and packs the
 *     filename/mime metadata. For ring uploads the wrap binds
 *     `asset_id`, which is why the callback runs AFTER init.
 *
 * This mirrors the existing single-shot upload page pattern so the two
 * paths can share the same key-wrapping + metadata logic.
 */
export async function uploadStream(
  file: File,
  perAssetKey: Uint8Array,
  apiUrl: string,
  opts: StreamingUploadOptions,
): Promise<StreamCommitResponse> {
  if (perAssetKey.length !== 32) {
    throw new Error("per-asset key must be 32 bytes");
  }

  const chunkSize = opts.chunkSize ?? DEFAULT_CHUNK_SIZE;
  const wasm = await loadStreamingWasm();

  // 1. Init — tell the server we're starting a stream. Returns six
  //    S3 multipart upload IDs, one per shard.
  const initResp = await fetch(`${apiUrl}/vault/stream/init`, {
    method: "POST",
    credentials: "include",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      content_length_hint: file.size,
      ring_id: opts.ringId,
    }),
  });
  if (!initResp.ok) {
    throw new Error(
      `stream/init failed: ${initResp.status} ${await initResp.text()}`,
    );
  }
  const init = (await initResp.json()) as StreamInitResponse;
  if (init.shards.length !== TOTAL_SHARDS) {
    throw new Error(
      `stream/init returned ${init.shards.length} shards, expected ${TOTAL_SHARDS}`,
    );
  }
  const assetId = init.asset_id;

  // Prepare the commit metadata now that we have the asset_id. Ring
  // uploads NEED this to happen post-init because the wrap binds
  // asset_id via HKDF. Personal uploads can technically wrap upfront
  // but we go through the callback for consistency. A failure here
  // triggers the abort path in the outer try/catch.
  let commitMeta: CommitMeta;
  try {
    commitMeta = await opts.prepareCommitMeta(assetId);
  } catch (err) {
    await fetch(
      `${apiUrl}/vault/stream/${encodeURIComponent(assetId)}/abort`,
      { method: "POST", credentials: "include" },
    ).catch(() => {});
    throw err;
  }

  // 2. Build per-shard buffers. One `ShardBuffer` per erasure shard;
  //    they hold bytes and flush S3 parts as the threshold is crossed.
  //    Each buffer also carries a running BLAKE3 hasher that produces
  //    the shard's expected content hash for Track 2 verification.
  //    All six share a single AdaptiveBandwidthController so the
  //    throttle state is global, not per-shard (Track 3).
  const bandwidth = new AdaptiveBandwidthController();
  const shardBuffers: ShardBuffer[] = [];
  for (let i = 0; i < TOTAL_SHARDS; i++) {
    shardBuffers.push(
      new ShardBuffer(
        i,
        assetId,
        apiUrl,
        new wasm.WasmBlake3Hasher(),
        bandwidth,
      ),
    );
  }

  // 3. Stream the file through the encryptor + erasure encoder.
  //
  //    We wrap this in a try/catch so that any failure mid-stream
  //    triggers an `abort` on the server side. Otherwise the six
  //    in-flight multipart uploads linger and cost money until the
  //    S3 lifecycle rule (if any) reaps them.
  try {
    const encryptor = new wasm.WasmStreamEncryptor(perAssetKey, chunkSize);
    const encoder = new wasm.WasmStreamEncoder();

    let offset = 0;
    while (offset < file.size) {
      const end = Math.min(offset + chunkSize, file.size);
      const isLast = end >= file.size;
      const slice = new Uint8Array(await file.slice(offset, end).arrayBuffer());

      // Encrypt the chunk. `sealChunk` returns JSON
      //   { counter, is_last, ciphertext_b64 }
      // and `ciphertext_b64` is the chunk's Poly1305-sealed bytes.
      const sealedJson = JSON.parse(encryptor.sealChunk(slice, isLast)) as {
        counter: number;
        is_last: boolean;
        ciphertext_b64: string;
      };
      const ciphertext = base64ToBytes(sealedJson.ciphertext_b64);

      // Erasure-encode the ciphertext. `encodeGroup` returns
      //   { group_index, shards_b64: [s0, s1, s2, s3, s4, s5] }.
      // Each shard-chunk goes into its matching ShardBuffer.
      const groupJson = JSON.parse(encoder.encodeGroup(ciphertext)) as {
        group_index: number;
        shards_b64: string[];
      };
      if (groupJson.shards_b64.length !== TOTAL_SHARDS) {
        throw new Error(
          `erasure encodeGroup returned ${groupJson.shards_b64.length} shards, expected ${TOTAL_SHARDS}`,
        );
      }
      for (let i = 0; i < TOTAL_SHARDS; i++) {
        await shardBuffers[i].append(base64ToBytes(groupJson.shards_b64[i]));
      }

      offset = end;
      opts.onProgress?.(offset, file.size);
      opts.onBandwidth?.({
        state: bandwidth.getState(),
        currentSpeedBps: bandwidth.getCurrentSpeedBps(),
        overallThroughputBps: bandwidth.getOverallThroughputBps(),
        interBlockDelayMs: bandwidth.getInterBlockDelayMs(),
      });
    }

    // 4. Flush the final (possibly-sub-5MB) part for every shard.
    for (const buf of shardBuffers) {
      await buf.flushFinal();
    }

    // 5. Build the commit payload. We hand the backend the full
    //    StreamManifest and StreamHeader verbatim — these are opaque
    //    to TS and get stashed in `_manifest/{id}.json` for readers.
    const streamManifest = JSON.parse(encoder.finishJson());
    const streamHeader = buildStreamHeaderSerdeJson(encryptor.headerJson());

    const shardsForCommit = shardBuffers.map((buf, i) => ({
      shard_index: i,
      parts: buf.completed,
    }));

    // Finalize the per-shard BLAKE3 hashers. Must happen exactly once
    // per shard — calling update/finalize in the wrong order against
    // the WASM hasher returns the empty-input digest and silently
    // breaks Track 2 verification. Order matches `shardBuffers`.
    const expectedShardHashesHex = shardBuffers.map((buf) =>
      buf.expectedHashHex(),
    );
    // Chunk 2.2: server HeadObjects each shard and rejects commit if
    // ContentLength ≠ our sum. Shipped as a flat Vec<u64> in request
    // order to match `expected_shard_hashes_hex`.
    const expectedShardBytes = shardBuffers.map((buf) => buf.totalBytes);

    const commitResp = await fetch(
      `${apiUrl}/vault/stream/${encodeURIComponent(assetId)}/commit`,
      {
        method: "POST",
        credentials: "include",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          stream_manifest: streamManifest,
          stream_header: streamHeader,
          shards: shardsForCommit,
          expected_shard_hashes_hex: expectedShardHashesHex,
          expected_shard_bytes: expectedShardBytes,
          wrapped_key_b64: commitMeta.wrappedKeyB64,
          encrypted_meta_b64: commitMeta.encryptedMetaB64,
          ring_id: opts.ringId,
          uploader_pubkey_x25519_b64: commitMeta.uploaderPubkeyX25519B64,
        }),
      },
    );
    if (!commitResp.ok) {
      // Track 2 Chunk 2.4 — a 422 from `/vault/stream/*/commit`
      // carries structured absorption failure info. Surface it as a
      // typed error the upload page can render nicely instead of the
      // raw backend text.
      if (commitResp.status === 422) {
        const body = (await commitResp.json().catch(() => null)) as {
          code?: string;
          reason?: string;
          failed_shard_indices?: number[];
        } | null;
        if (body?.code === "absorption_failed") {
          const err = new Error(
            `Absorption check failed (${body.reason ?? "unknown"}) — shards ${
              body.failed_shard_indices?.join(", ") ?? "unknown"
            } did not land correctly. Please try uploading again.`,
          );
          (err as Error & { code?: string; absorption?: unknown }).code =
            "absorption_failed";
          (err as Error & { code?: string; absorption?: unknown }).absorption =
            body;
          throw err;
        }
      }
      throw new Error(
        `stream/commit failed: ${commitResp.status} ${await commitResp.text()}`,
      );
    }
    return (await commitResp.json()) as StreamCommitResponse;
  } catch (err) {
    // Best-effort cleanup. Swallow any abort failure because we want
    // to re-throw the ORIGINAL error, not mask it with a cleanup
    // error. The S3 lifecycle rule (if configured) will eventually
    // reap any still-in-flight uploads.
    try {
      await fetch(
        `${apiUrl}/vault/stream/${encodeURIComponent(assetId)}/abort`,
        { method: "POST", credentials: "include" },
      );
    } catch {
      // ignore
    }
    throw err;
  }
}

/**
 * Translate the WASM-bindings header wrapper `{stream_id_b64, chunk_size}`
 * into the serde-native `StreamHeader` shape the Rust backend expects:
 * `{stream_id: [u8; 20], chunk_size: u32}` where `stream_id` is a JSON
 * array of 20 numbers. The bindings wrapper exists to avoid exposing a
 * raw byte array through the FFI; the backend never sees the wrapper.
 */
function buildStreamHeaderSerdeJson(wasmHeaderJson: string): {
  stream_id: number[];
  chunk_size: number;
} {
  const parsed = JSON.parse(wasmHeaderJson) as {
    stream_id_b64: string;
    chunk_size: number;
  };
  const bytes = base64ToBytes(parsed.stream_id_b64);
  if (bytes.length !== 20) {
    throw new Error(`stream_id must be 20 bytes, got ${bytes.length}`);
  }
  return {
    stream_id: Array.from(bytes),
    chunk_size: parsed.chunk_size,
  };
}

// `bytesToBase64` is re-exported for symmetry — callers building
// `wrapped_key_b64` / `encrypted_meta_b64` often want this helper.
export { bytesToBase64 };
