"use client";

import { Suspense, useCallback, useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import { getCrypto, hexToBytes, bytesToBase64, API_URL } from "../lib/resqdCrypto";

type FetchState =
  | { phase: "idle" }
  | { phase: "requesting" }
  | { phase: "downloading-shards"; done: number; total: number }
  | { phase: "reconstructing" }
  | { phase: "decrypting" }
  | {
      phase: "done";
      bytes: Uint8Array;
      sequence: string | null;
      canaryHash: string | null;
    }
  | { phase: "error"; message: string };

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
}

function FetchInner() {
  const params = useSearchParams();
  const [assetId, setAssetId] = useState(params.get("id") || "");
  const [keyHex, setKeyHex] = useState(params.get("key") || "");
  const [state, setState] = useState<FetchState>({ phase: "idle" });
  const [expectedCount, setExpectedCount] = useState<string>("");
  const [verifyResult, setVerifyResult] = useState<string>("");

  // Auto-run once if URL params are present.
  useEffect(() => {
    if (params.get("id") && params.get("key")) {
      fetchAndDecrypt();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const fetchAndDecrypt = useCallback(async () => {
    try {
      if (!assetId || !keyHex) {
        setState({ phase: "error", message: "asset id and key required" });
        return;
      }

      // ───────── REQUEST METADATA + 6 SHARD URLS ─────────
      setState({ phase: "requesting" });
      const metaResp = await fetch(`${API_URL}/vault/${encodeURIComponent(assetId)}`);
      if (!metaResp.ok) {
        throw new Error(`api ${metaResp.status}: ${await metaResp.text()}`);
      }
      const sequence = metaResp.headers.get("x-resqd-canary-sequence");
      const canaryHash = metaResp.headers.get("x-resqd-canary-hash");
      const contentType = metaResp.headers.get("content-type") || "";

      let plaintextBytes: Uint8Array;

      if (contentType.includes("application/json")) {
        // SHARDED MODE — new path
        const manifest: ShardedFetchResponse = await metaResp.json();
        if (manifest.mode !== "sharded") {
          throw new Error(`unexpected mode: ${manifest.mode}`);
        }

        // ───────── DOWNLOAD ALL AVAILABLE SHARDS IN PARALLEL ─────────
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
            `only ${present}/${manifest.data_shards} required shards available — vault is degraded`,
          );
        }

        // ───────── RECONSTRUCT + DECRYPT (WASM) ─────────
        setState({ phase: "reconstructing" });
        const crypto = await getCrypto();
        const encryptedBytes = crypto.erasure_reconstruct(
          JSON.stringify(shardResults),
          manifest.original_len,
        );
        const blobJson = new TextDecoder().decode(encryptedBytes);

        setState({ phase: "decrypting" });
        const key = hexToBytes(keyHex);
        plaintextBytes = crypto.decrypt_data(key, blobJson);
      } else {
        // LEGACY INLINE MODE — small-file bytes come back directly
        const ciphertextJson = await metaResp.text();
        setState({ phase: "decrypting" });
        const crypto = await getCrypto();
        const key = hexToBytes(keyHex);
        plaintextBytes = crypto.decrypt_data(key, ciphertextJson);
      }

      setState({
        phase: "done",
        bytes: plaintextBytes,
        sequence,
        canaryHash,
      });
    } catch (e) {
      setState({
        phase: "error",
        message: e instanceof Error ? e.message : String(e),
      });
    }
  }, [assetId, keyHex]);

  const verify = useCallback(async () => {
    try {
      const count = parseInt(expectedCount, 10);
      if (Number.isNaN(count)) {
        setVerifyResult("expected count must be a number");
        return;
      }
      const resp = await fetch(
        `${API_URL}/vault/${encodeURIComponent(assetId)}/verify?count=${count}`,
      );
      if (!resp.ok) {
        setVerifyResult(`api error: ${resp.status}`);
        return;
      }
      const data = await resp.json();
      setVerifyResult(
        `on-chain count: ${data.on_chain_access_count} — ${
          data.matches ? "✓ matches" : "✗ mismatch"
        }`,
      );
    } catch (e) {
      setVerifyResult(e instanceof Error ? e.message : String(e));
    }
  }, [assetId, expectedCount]);

  const download = useCallback(() => {
    if (state.phase !== "done") return;
    const blob = new Blob([new Uint8Array(state.bytes)], {
      type: "application/octet-stream",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `resqd-${assetId.slice(0, 8)}.bin`;
    a.click();
    URL.revokeObjectURL(url);
  }, [state, assetId]);

  const preview =
    state.phase === "done" && state.bytes.length < 4096
      ? new TextDecoder("utf-8", { fatal: false }).decode(state.bytes)
      : null;

  return (
    <main className="mx-auto max-w-2xl px-6 py-12 text-slate-100">
      <h1 className="text-3xl font-bold mb-2">Fetch from RESQD</h1>
      <p className="text-sm text-slate-400 mb-8">
        Each fetch rotates the canary and anchors a new commitment on Base
        Sepolia. Shards are downloaded directly from storage backends and
        reassembled in your browser. Your key never leaves the browser.
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
        <div>
          <label className="block text-xs font-medium text-slate-400 uppercase tracking-wide mb-1">
            Encryption key (hex)
          </label>
          <input
            type="text"
            value={keyHex}
            onChange={(e) => setKeyHex(e.target.value)}
            className="w-full bg-slate-900 border border-slate-800 rounded-lg p-2 text-xs font-mono"
          />
        </div>
        <button
          onClick={fetchAndDecrypt}
          disabled={!assetId || !keyHex}
          className="rounded-lg bg-amber-500 text-slate-900 font-medium px-5 py-2 text-sm disabled:opacity-30"
        >
          Fetch & Decrypt
        </button>
      </section>

      <section className="bg-slate-900 border border-slate-800 rounded-xl p-5 min-h-24">
        {state.phase === "idle" && (
          <p className="text-slate-500 text-sm">
            Paste an asset id + key, then click Fetch.
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
            <p className="text-xs text-slate-400">
              canary sequence after rotation:{" "}
              <span className="font-mono text-amber-300">{state.sequence}</span>
            </p>
            <p className="text-xs text-slate-400 break-all">
              new commitment hash:{" "}
              <span className="font-mono">{state.canaryHash}</span>
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
              Download bytes
            </button>
          </div>
        )}
      </section>

      <section className="mt-8 border-t border-slate-800 pt-6">
        <h2 className="text-sm font-semibold mb-2">Verify on-chain access count</h2>
        <div className="flex gap-2">
          <input
            type="number"
            value={expectedCount}
            onChange={(e) => setExpectedCount(e.target.value)}
            placeholder="expected count"
            className="flex-1 bg-slate-900 border border-slate-800 rounded-lg p-2 text-sm"
          />
          <button
            onClick={verify}
            disabled={!assetId || !expectedCount}
            className="rounded-lg bg-slate-700 hover:bg-slate-600 px-4 py-2 text-sm disabled:opacity-30"
          >
            Verify
          </button>
        </div>
        {verifyResult && (
          <p className="mt-2 text-xs font-mono text-slate-300">{verifyResult}</p>
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
