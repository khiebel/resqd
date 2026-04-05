"use client";

import { useCallback, useEffect, useState } from "react";
import {
  getCrypto,
  bytesToHex,
  base64ToBytes,
  API_URL,
  type ErasureEncoded,
} from "../lib/resqdCrypto";

type UploadState =
  | { phase: "idle" }
  | { phase: "encrypting" }
  | { phase: "erasure-coding" }
  | { phase: "init" }
  | { phase: "uploading"; progress: number }
  | { phase: "committing" }
  | {
      phase: "done";
      assetId: string;
      keyHex: string;
      originalLen: number;
      anchored: boolean;
      canaryHashHex: string;
    }
  | { phase: "error"; message: string };

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
  const [keyHex, setKeyHex] = useState<string>("");

  // Generate a fresh encryption key on mount. WASM loads lazily.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const crypto = await getCrypto();
        const key = crypto.generate_random_key();
        if (!cancelled) setKeyHex(bytesToHex(key));
      } catch (e) {
        console.error("wasm init failed", e);
        if (!cancelled)
          setState({
            phase: "error",
            message: `failed to load crypto module: ${
              e instanceof Error ? e.message : String(e)
            }`,
          });
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const handleFile = useCallback(
    async (file: File) => {
      if (!keyHex) {
        setState({ phase: "error", message: "crypto module not ready yet" });
        return;
      }
      try {
        // ───────── ENCRYPT (in browser, WASM) ─────────
        setState({ phase: "encrypting" });
        const crypto = await getCrypto();
        const plaintext = new Uint8Array(await file.arrayBuffer());
        const keyBytes = new Uint8Array(
          keyHex.match(/.{2}/g)!.map((b) => parseInt(b, 16)),
        );
        const blobJson = crypto.encrypt_data(keyBytes, plaintext);
        const encryptedBytes = new TextEncoder().encode(blobJson);
        const originalLen = encryptedBytes.length;

        // ───────── ERASURE CODE (in browser, WASM) ─────────
        setState({ phase: "erasure-coding" });
        const encodedJson = crypto.erasure_encode(encryptedBytes);
        const encoded: ErasureEncoded = JSON.parse(encodedJson);

        // ───────── REQUEST 6 PRESIGNED SLOTS ─────────
        setState({ phase: "init" });
        const initResp = await fetch(`${API_URL}/vault/init`, {
          method: "POST",
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

        // ───────── UPLOAD ALL SHARDS IN PARALLEL ─────────
        setState({ phase: "uploading", progress: 0 });
        let done = 0;
        await Promise.all(
          init.shards.map(async (slot) => {
            const shardBytes = base64ToBytes(encoded.shards[slot.index]);
            const resp = await fetch(slot.upload_url, {
              method: "PUT",
              headers: { "content-type": "application/octet-stream" },
              // Wrap in Blob to satisfy strict TS BodyInit typing for
              // Uint8Array<ArrayBufferLike>.
              body: new Blob([new Uint8Array(shardBytes)]),
            });
            if (!resp.ok) {
              throw new Error(
                `shard ${slot.index} PUT failed: ${resp.status}`,
              );
            }
            done += 1;
            setState({ phase: "uploading", progress: done / init.shards.length });
          }),
        );

        // ───────── COMMIT (creates canary + anchors on-chain) ─────────
        setState({ phase: "committing" });
        const commitResp = await fetch(
          `${API_URL}/vault/${encodeURIComponent(init.asset_id)}/commit`,
          {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ original_len: originalLen }),
          },
        );
        if (!commitResp.ok) {
          throw new Error(`commit failed: ${await commitResp.text()}`);
        }
        const commit: CommitResponse = await commitResp.json();

        setState({
          phase: "done",
          assetId: commit.asset_id,
          keyHex,
          originalLen: commit.original_len,
          anchored: commit.anchored_on_chain,
          canaryHashHex: commit.canary_hash_hex,
        });
      } catch (e) {
        setState({
          phase: "error",
          message: e instanceof Error ? e.message : String(e),
        });
      }
    },
    [keyHex],
  );

  return (
    <main className="mx-auto max-w-2xl px-6 py-12 text-slate-100">
      <h1 className="text-3xl font-bold mb-2">Upload to RESQD</h1>
      <p className="text-sm text-slate-400 mb-8">
        Your file is encrypted in your browser, erasure-coded into 6 shards
        via Reed-Solomon (4+2), and each shard is uploaded directly to a
        storage backend. RESQD never sees plaintext, and the canary
        commitment is anchored on Base Sepolia before this page returns.
      </p>

      <section className="mb-6">
        <label className="block text-xs font-medium text-slate-400 uppercase tracking-wide mb-2">
          Your encryption key (save this — required to decrypt)
        </label>
        <code className="block bg-slate-900 border border-slate-800 rounded-lg p-3 text-xs font-mono text-amber-300 break-all">
          {keyHex || "(loading crypto module…)"}
        </code>
      </section>

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
          {state.phase === "encrypting" && "Step 1/5 — Encrypting in your browser…"}
          {state.phase === "erasure-coding" &&
            "Step 2/5 — Erasure-coding into 6 shards…"}
          {state.phase === "init" && "Step 3/5 — Requesting presigned upload URLs…"}
          {state.phase === "uploading" &&
            `Step 4/5 — Uploading shards (${Math.round(state.progress * 100)}%)…`}
          {state.phase === "committing" &&
            "Step 5/5 — Anchoring canary on Base Sepolia…"}
          {state.phase === "done" && "Done — see details below"}
          {state.phase === "error" && (
            <span className="text-red-400">Error: {state.message}</span>
          )}
        </p>
      </section>

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
                Canary commitment (sequence 0)
              </dt>
              <dd className="font-mono text-xs break-all">
                {state.canaryHashHex}
              </dd>
            </div>
            <div>
              <dt className="text-slate-400 text-xs uppercase">
                Anchored on Base Sepolia
              </dt>
              <dd>{state.anchored ? "✓ yes" : "✗ no"}</dd>
            </div>
          </dl>
          <a
            href={`/fetch/?id=${encodeURIComponent(state.assetId)}&key=${encodeURIComponent(state.keyHex)}`}
            className="inline-block mt-3 text-sm text-amber-400 hover:underline"
          >
            → Open fetch page (rotates canary)
          </a>
        </section>
      )}
    </main>
  );
}
