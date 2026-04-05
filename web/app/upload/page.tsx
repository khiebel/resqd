"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import {
  getCrypto,
  base64ToBytes,
  API_URL,
  type ErasureEncoded,
} from "../lib/resqdCrypto";
import { loadMasterKey, fetchMe, type SessionUser } from "../lib/passkey";

type UploadState =
  | { phase: "idle" }
  | { phase: "wrapping-key" }
  | { phase: "encrypting" }
  | { phase: "erasure-coding" }
  | { phase: "init" }
  | { phase: "uploading"; progress: number }
  | { phase: "committing" }
  | {
      phase: "done";
      assetId: string;
      originalLen: number;
      anchored: boolean;
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
  const [user, setUser] = useState<SessionUser | null>(null);

  // Guard: must be signed in AND have a PRF master key cached in this tab.
  // Missing either → bounce to /login so the user gets a Touch ID prompt
  // before being allowed to upload.
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
    })();
  }, []);

  const handleFile = useCallback(async (file: File) => {
    try {
      const masterKey = loadMasterKey();
      if (!masterKey) {
        window.location.href = "/login/";
        return;
      }

      // ───────── WRAP FRESH PER-ASSET KEY + METADATA UNDER MASTER ─────────
      // Each asset gets its own 32-byte XChaCha20 key. We seal that key
      // under the PRF-derived master key and ship the sealed blob with
      // the commit. Only holders of the passkey (and therefore the
      // master key) can ever unwrap it — the server just round-trips it.
      //
      // The filename + MIME type are also sealed under the master key
      // (separate encryption, distinct nonce) so the /vault listing can
      // show real filenames instead of UUIDs without ever exposing them
      // to the server. Using master here instead of per-asset means the
      // client can decrypt the list view with just one key.
      setState({ phase: "wrapping-key" });
      const crypto = await getCrypto();
      const perAssetKey = crypto.generate_random_key();
      const wrappedJson = crypto.encrypt_data(masterKey, perAssetKey);
      const wrappedB64 = btoa(wrappedJson);

      const metaJson = crypto.encrypt_data(
        masterKey,
        new TextEncoder().encode(
          JSON.stringify({
            name: file.name,
            mime: file.type || "application/octet-stream",
          }),
        ),
      );
      const encryptedMetaB64 = btoa(metaJson);

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

      // ───────── COMMIT (persists wrapped key + owner + anchors) ─────────
      setState({ phase: "committing" });
      const commitResp = await fetch(
        `${API_URL}/vault/${encodeURIComponent(init.asset_id)}/commit`,
        {
          method: "POST",
          credentials: "include",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            original_len: originalLen,
            wrapped_key_b64: wrappedB64,
            encrypted_meta_b64: encryptedMetaB64,
          }),
        },
      );
      if (!commitResp.ok) {
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
      setState({
        phase: "error",
        message: e instanceof Error ? e.message : String(e),
      });
    }
  }, []);

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
          {state.phase === "uploading" &&
            `Step 5/6 — Uploading shards (${Math.round(state.progress * 100)}%)…`}
          {state.phase === "committing" &&
            "Step 6/6 — Anchoring canary on Base Sepolia…"}
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
