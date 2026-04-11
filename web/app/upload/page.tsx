"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import {
  getCrypto,
  base64ToBytes,
  API_URL,
  type ErasureEncoded,
} from "../lib/resqdCrypto";
import {
  uploadStream,
  type CommitMeta,
  type BandwidthSnapshot,
} from "../lib/streamingUploader";
import {
  loadMasterKey,
  fetchMe,
  loadX25519Identity,
  ensureRingPrivkey,
  type SessionUser,
} from "../lib/passkey";

/**
 * Files above this threshold use the streaming upload path
 * (`/vault/stream/*` + direct-to-S3 multipart). Smaller files use
 * the legacy single-shot path which is fine for anything under
 * roughly 200 MB — the WASM memory ceiling that the streaming path
 * was built to escape.
 */
const STREAMING_THRESHOLD_BYTES = 100 * 1024 * 1024; // 100 MB

interface RingSummary {
  ring_id: string;
  name: string;
  role: string;
}

interface RingMeResponse {
  ring_pubkey_x25519_b64?: string;
}

type UploadState =
  | { phase: "idle" }
  | { phase: "wrapping-key" }
  | { phase: "encrypting" }
  | { phase: "erasure-coding" }
  | { phase: "init" }
  | { phase: "uploading"; progress: number; bandwidth?: BandwidthSnapshot }
  | { phase: "committing" }
  | {
      phase: "done";
      assetId: string;
      originalLen: number;
      anchored: boolean;
    }
  | {
      phase: "error";
      message: string;
      /** When set, the structured server rejection — shown specially. */
      absorption?: {
        reason?: string;
        failed_shard_indices?: number[];
      };
    };

interface InitResponse {
  asset_id: string;
  data_shards: number;
  parity_shards: number;
  shards: { index: number; upload_url: string }[];
  ttl_seconds: number;
}

interface CommitResponse {
  asset_id: string;
  original_len: number;
  canary_sequence: number;
  canary_hash_hex: string;
  anchored_on_chain: boolean;
  data_shards: number;
  parity_shards: number;
}

export default function UploadPage() {
  const [state, setState] = useState<UploadState>({ phase: "idle" });
  const [user, setUser] = useState<SessionUser | null>(null);
  const [rings, setRings] = useState<RingSummary[]>([]);
  const [selectedRingId, setSelectedRingId] = useState<string>("");

  useEffect(() => {
    (async () => {
      const me = await fetchMe();
      if (!me) {
        window.location.href = "/login/";
        return;
      }
      if (!loadMasterKey()) {
        window.location.href = "/login/";
        return;
      }
      setUser(me);

      // Load rings so we can show a ring selector. Only show rings
      // where the user has a write role (Owner or Adult).
      try {
        const resp = await fetch(`${API_URL}/rings`, {
          credentials: "include",
        });
        if (resp.ok) {
          const all: RingSummary[] = await resp.json();
          setRings(
            all.filter(
              (r) => r.role === "owner" || r.role === "adult",
            ),
          );
        }
      } catch {
        // Rings are optional — if the fetch fails, the user just
        // doesn't see the ring selector. No error.
      }
    })();
  }, []);

  const handleFile = useCallback(async (file: File) => {
    try {
      const masterKey = loadMasterKey();
      if (!masterKey) {
        window.location.href = "/login/";
        return;
      }

      // ───────── DETERMINE TARGET (personal vs ring) ─────────
      const isRingUpload = !!selectedRingId;
      let ringPubB64: string | undefined;
      let uploaderPubB64: string | undefined;

      if (isRingUpload) {
        const ident = loadX25519Identity();
        if (!ident) {
          throw new Error("X25519 identity not loaded — re-login");
        }
        uploaderPubB64 = ident.pubB64;

        // Fetch ring pubkey.
        const meResp = await fetch(
          `${API_URL}/rings/${encodeURIComponent(selectedRingId)}/me`,
          { credentials: "include" },
        );
        if (!meResp.ok) throw new Error("ring membership check failed");
        const meData = (await meResp.json()) as RingMeResponse;
        ringPubB64 = meData.ring_pubkey_x25519_b64;
        if (!ringPubB64) throw new Error("ring pubkey not found");
      }

      // ───────── WRAP FRESH PER-ASSET KEY ─────────
      //
      // Personal upload: seal under master key.
      // Ring upload: seal under sender_wrap_key(uploader_priv,
      //   ring_pub, asset_id). We need the asset_id first, so we
      //   call /vault/init to get it, THEN wrap. Restructured below.
      setState({ phase: "wrapping-key" });
      const crypto = await getCrypto();
      const perAssetKey = crypto.generate_random_key();

      // ───────── LARGE FILE → STREAMING PATH ─────────
      //
      // Files above STREAMING_THRESHOLD_BYTES use `/vault/stream/*`
      // and PUT shard-chunks directly to S3 multipart. The single-shot
      // path below holds the whole file in WASM memory and caps out
      // around 200 MB; the streaming path has no practical ceiling.
      if (file.size > STREAMING_THRESHOLD_BYTES) {
        setState({ phase: "uploading", progress: 0 });
        const metaPlaintext = new TextEncoder().encode(
          JSON.stringify({
            name: file.name,
            mime: file.type || "application/octet-stream",
          }),
        );

        let lastBandwidth: BandwidthSnapshot | undefined;
        const commit = await uploadStream(file, perAssetKey, API_URL, {
          ringId: isRingUpload ? selectedRingId : undefined,
          onProgress: (bytesProcessed, totalBytes) => {
            setState({
              phase: "uploading",
              progress: totalBytes > 0 ? bytesProcessed / totalBytes : 0,
              bandwidth: lastBandwidth,
            });
          },
          onBandwidth: (snapshot) => {
            lastBandwidth = snapshot;
          },
          prepareCommitMeta: (assetId): CommitMeta => {
            // Ring uploads bind `asset_id` via HKDF in the wrap key,
            // so this runs AFTER stream/init. Personal uploads could
            // wrap earlier but go through the callback for symmetry.
            if (isRingUpload && ringPubB64 && uploaderPubB64) {
              const ident = loadX25519Identity()!;
              const wrapKeyB64 = crypto.x25519_sender_wrap_key(
                ident.privB64,
                ringPubB64,
                assetId,
              );
              const wrapKey = base64ToBytes(wrapKeyB64);
              return {
                wrappedKeyB64: btoa(
                  crypto.encrypt_data(wrapKey, perAssetKey),
                ),
                encryptedMetaB64: btoa(
                  crypto.encrypt_data(wrapKey, metaPlaintext),
                ),
                uploaderPubkeyX25519B64: uploaderPubB64,
              };
            }
            return {
              wrappedKeyB64: btoa(
                crypto.encrypt_data(masterKey, perAssetKey),
              ),
              encryptedMetaB64: btoa(
                crypto.encrypt_data(masterKey, metaPlaintext),
              ),
            };
          },
        });

        setState({
          phase: "done",
          assetId: commit.asset_id,
          originalLen: commit.total_input_bytes,
          anchored: commit.anchored_on_chain,
        });
        return;
      }

      // ───────── FRAME + ENCRYPT ─────────
      setState({ phase: "encrypting" });
      const bodyBytes = new Uint8Array(await file.arrayBuffer());
      const headerBytes = new TextEncoder().encode(
        JSON.stringify({
          v: 1,
          name: file.name,
          mime: file.type || "application/octet-stream",
        }),
      );
      const plaintext = new Uint8Array(4 + headerBytes.length + bodyBytes.length);
      new DataView(plaintext.buffer).setUint32(0, headerBytes.length, true);
      plaintext.set(headerBytes, 4);
      plaintext.set(bodyBytes, 4 + headerBytes.length);

      const blobJson = crypto.encrypt_data(perAssetKey, plaintext);
      const encryptedBytes = new TextEncoder().encode(blobJson);
      const originalLen = encryptedBytes.length;

      // ───────── ERASURE CODE ─────────
      setState({ phase: "erasure-coding" });
      const encodedJson = crypto.erasure_encode(encryptedBytes);
      const encoded: ErasureEncoded = JSON.parse(encodedJson);

      // ───────── INIT (presigned slots) ─────────
      // We need the server-generated asset_id BEFORE wrapping the
      // per-asset key for ring uploads (the HKDF info binds asset_id).
      setState({ phase: "init" });
      const initResp = await fetch(`${API_URL}/vault/init`, {
        method: "POST",
        credentials: "include",
        headers: { "content-type": "application/json" },
        body: "{}",
      });
      if (!initResp.ok) {
        throw new Error(`init failed: ${initResp.status} ${await initResp.text()}`);
      }
      const init: InitResponse = await initResp.json();
      if (init.shards.length !== encoded.shards.length) {
        throw new Error(
          `server wanted ${init.shards.length} shards, WASM produced ${encoded.shards.length}`,
        );
      }

      // ───────── WRAP PER-ASSET KEY + META (now that we have asset_id) ─────
      let wrappedB64: string;
      let encryptedMetaB64: string;
      const metaPlaintext = new TextEncoder().encode(
        JSON.stringify({
          name: file.name,
          mime: file.type || "application/octet-stream",
        }),
      );

      if (isRingUpload && ringPubB64 && uploaderPubB64) {
        const ident = loadX25519Identity()!;
        const wrapKeyB64 = crypto.x25519_sender_wrap_key(
          ident.privB64,
          ringPubB64,
          init.asset_id,
        );
        const wrapKey = base64ToBytes(wrapKeyB64);
        wrappedB64 = btoa(crypto.encrypt_data(wrapKey, perAssetKey));
        encryptedMetaB64 = btoa(crypto.encrypt_data(wrapKey, metaPlaintext));
      } else {
        wrappedB64 = btoa(crypto.encrypt_data(masterKey, perAssetKey));
        encryptedMetaB64 = btoa(crypto.encrypt_data(masterKey, metaPlaintext));
      }

      // ───────── UPLOAD SHARDS IN PARALLEL ─────────
      setState({ phase: "uploading", progress: 0 });
      let done = 0;
      await Promise.all(
        init.shards.map(async (slot) => {
          const shardBytes = base64ToBytes(encoded.shards[slot.index]);
          const resp = await fetch(slot.upload_url, {
            method: "PUT",
            headers: { "content-type": "application/octet-stream" },
            body: new Blob([new Uint8Array(shardBytes)]),
          });
          if (!resp.ok) {
            throw new Error(`shard ${slot.index} PUT failed: ${resp.status}`);
          }
          done += 1;
          setState({ phase: "uploading", progress: done / init.shards.length });
        }),
      );

      // ───────── COMMIT ─────────
      setState({ phase: "committing" });
      const commitBody: Record<string, unknown> = {
        original_len: originalLen,
        wrapped_key_b64: wrappedB64,
        encrypted_meta_b64: encryptedMetaB64,
      };
      if (isRingUpload) {
        commitBody.ring_id = selectedRingId;
        commitBody.uploader_pubkey_x25519_b64 = uploaderPubB64;
      }
      const commitResp = await fetch(
        `${API_URL}/vault/${encodeURIComponent(init.asset_id)}/commit`,
        {
          method: "POST",
          credentials: "include",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(commitBody),
        },
      );
      if (!commitResp.ok) {
        // 413 from the server means quota exceeded — surface the
        // specific numbers so the user knows what to delete.
        if (commitResp.status === 413) {
          const body = await commitResp.json().catch(() => ({}));
          const used = body.storage_used_bytes ?? 0;
          const cap = body.storage_quota_bytes ?? 0;
          const req = body.requested_bytes ?? 0;
          const fmt = (n: number) =>
            n < 1024 * 1024
              ? `${(n / 1024).toFixed(1)} KB`
              : `${(n / 1024 / 1024).toFixed(1)} MB`;
          throw new Error(
            `Your vault is full. ${fmt(used)} of ${fmt(cap)} used, this file would add ${fmt(req)}. Delete something first.`,
          );
        }
        throw new Error(`commit failed: ${await commitResp.text()}`);
      }
      const commit: CommitResponse = await commitResp.json();

      setState({
        phase: "done",
        assetId: commit.asset_id,
        originalLen: commit.original_len,
        anchored: commit.anchored_on_chain,
      });
    } catch (e) {
      // Track 2 Chunk 2.4 — the structured absorption-failed error
      // thrown by `streamingUploader` carries a `code` field and an
      // `absorption` payload with the shards that drifted. Surface
      // those specifically; other errors fall through to the generic
      // message path.
      const err = e as Error & {
        code?: string;
        absorption?: { reason?: string; failed_shard_indices?: number[] };
      };
      if (err.code === "absorption_failed") {
        setState({
          phase: "error",
          message: err.message,
          absorption: err.absorption,
        });
      } else {
        setState({
          phase: "error",
          message: err instanceof Error ? err.message : String(err),
        });
      }
    }
  }, [selectedRingId]);

  return (
    <main className="mx-auto max-w-2xl px-6 py-12 text-slate-100">
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-3xl font-bold">Upload to RESQD</h1>
        {user && (
          <Link
            href="/vault/"
            className="text-xs text-amber-400 hover:underline"
          >
            My vault →
          </Link>
        )}
      </div>
      <p className="text-sm text-slate-400 mb-8">
        Your file is encrypted in your browser with a fresh per-asset key,
        erasure-coded into 6 shards, and uploaded directly to storage. The
        per-asset key is sealed under your passkey-derived master key —
        RESQD never sees plaintext or any key material. The canary
        commitment is anchored on Base Sepolia before this page returns.
      </p>

      {rings.length > 0 && (
        <section className="mb-6 bg-slate-900 border border-slate-800 rounded-lg p-4">
          <label className="block text-xs font-medium text-slate-400 uppercase tracking-wide mb-2">
            Upload to
          </label>
          <select
            value={selectedRingId}
            onChange={(e) => setSelectedRingId(e.target.value)}
            disabled={state.phase !== "idle"}
            className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm"
          >
            <option value="">My personal vault</option>
            {rings.map((r) => (
              <option key={r.ring_id} value={r.ring_id}>
                {r.name} (ring)
              </option>
            ))}
          </select>
          {selectedRingId && (
            <p className="mt-2 text-xs text-violet-300">
              This file will be owned by the ring. All ring members can
              read it. Only Owner and Adult roles can upload.
            </p>
          )}
        </section>
      )}

      <section
        className="border-2 border-dashed border-slate-700 rounded-xl p-10 text-center hover:border-slate-500 transition-colors cursor-pointer"
        onClick={() => document.getElementById("resqd-file-input")?.click()}
        onDragOver={(e) => e.preventDefault()}
        onDrop={(e) => {
          e.preventDefault();
          if (e.dataTransfer.files?.[0]) handleFile(e.dataTransfer.files[0]);
        }}
      >
        <input
          id="resqd-file-input"
          type="file"
          hidden
          onChange={(e) => e.target.files?.[0] && handleFile(e.target.files[0])}
        />
        <p className="text-slate-400">
          {state.phase === "idle" && "Click or drop a file to encrypt & upload"}
          {state.phase === "wrapping-key" &&
            "Step 1/6 — Sealing per-asset key under your passkey…"}
          {state.phase === "encrypting" && "Step 2/6 — Encrypting in your browser…"}
          {state.phase === "erasure-coding" &&
            "Step 3/6 — Erasure-coding into 6 shards…"}
          {state.phase === "init" && "Step 4/6 — Requesting presigned upload URLs…"}
          {state.phase === "uploading" && (
            <>
              {`Step 5/6 — Uploading shards (${Math.round(state.progress * 100)}%)…`}
              {state.bandwidth && (
                <BandwidthBadge snapshot={state.bandwidth} />
              )}
            </>
          )}
          {state.phase === "committing" &&
            "Step 6/6 — Anchoring canary on Base Sepolia…"}
          {state.phase === "done" && "Done — see details below"}
          {state.phase === "error" && (
            <span className="text-red-400">Error: {state.message}</span>
          )}
        </p>
      </section>

      {state.phase === "error" && state.absorption && (
        <section className="mt-6 bg-red-950/30 border border-red-800 rounded-xl p-5">
          <h2 className="text-sm font-semibold text-red-300 mb-2">
            Proof-of-absorption failed
          </h2>
          <p className="text-xs text-slate-300 mb-3">
            The server confirmed all shards reached S3, but the post-commit
            integrity check detected drift. Nothing was stored — the shards
            have been cleaned up. This can happen on a flaky network or a
            corrupted file read. Try uploading again; if the same file
            keeps failing, re-save a copy and try that.
          </p>
          <dl className="text-xs space-y-1 text-slate-400">
            <div>
              <dt className="inline text-slate-500">Reason:</dt>{" "}
              <dd className="inline font-mono">
                {state.absorption.reason ?? "unknown"}
              </dd>
            </div>
            {state.absorption.failed_shard_indices && (
              <div>
                <dt className="inline text-slate-500">Failed shards:</dt>{" "}
                <dd className="inline font-mono">
                  {state.absorption.failed_shard_indices.join(", ")}
                </dd>
              </div>
            )}
          </dl>
          <button
            type="button"
            onClick={() => setState({ phase: "idle" })}
            className="mt-4 inline-block bg-amber-500 text-slate-900 font-semibold px-4 py-2 rounded text-sm"
          >
            Try again
          </button>
        </section>
      )}

      {state.phase === "done" && (
        <section className="mt-8 bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-3">
          <h2 className="text-lg font-semibold text-green-400">✓ Vaulted</h2>
          <dl className="text-sm space-y-2">
            <div>
              <dt className="text-slate-400 text-xs uppercase">Asset ID</dt>
              <dd className="font-mono text-xs break-all">{state.assetId}</dd>
            </div>
            <div>
              <dt className="text-slate-400 text-xs uppercase">
                Encrypted bytes stored
              </dt>
              <dd>
                {state.originalLen.toLocaleString()} (sharded 4+2 across 6 backends)
              </dd>
            </div>
            <div>
              <dt className="text-slate-400 text-xs uppercase">
                Anchored on Base Sepolia
              </dt>
              <dd>{state.anchored ? "✓ yes" : "✗ no"}</dd>
            </div>
          </dl>
          <div className="flex gap-4 pt-2">
            <Link
              href="/vault/"
              className="text-sm text-amber-400 hover:underline"
            >
              → Back to my vault
            </Link>
            <Link
              href={`/fetch/?id=${encodeURIComponent(state.assetId)}`}
              className="text-sm text-slate-400 hover:underline"
            >
              → Open fetch page
            </Link>
          </div>
        </section>
      )}
    </main>
  );
}

/**
 * Polite-mode badge. Rendered during streaming uploads to show the
 * adaptive bandwidth controller's current state + throughput. When the
 * controller is backing off, surfaces a human-readable "yielding to
 * other traffic" hint. Track 3 Chunk 3.4.
 */
function BandwidthBadge({ snapshot }: { snapshot: BandwidthSnapshot }) {
  const mbps = (snapshot.overallThroughputBps / (1024 * 1024)).toFixed(1);
  const hint =
    snapshot.state === "backing_off"
      ? "polite mode — yielding to other traffic"
      : snapshot.state === "ramping"
        ? "ramping up"
        : snapshot.state === "calibrating"
          ? "calibrating baseline"
          : "steady";
  const pillClass =
    snapshot.state === "backing_off"
      ? "bg-amber-900/40 text-amber-300 border-amber-700/50"
      : "bg-slate-800 text-slate-400 border-slate-700";
  return (
    <span
      className={`ml-3 inline-block rounded-full border px-2 py-0.5 text-xs ${pillClass}`}
      title={`delay ${Math.round(snapshot.interBlockDelayMs)}ms`}
    >
      {mbps} MB/s · {hint}
    </span>
  );
}
