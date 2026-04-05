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
  loadMasterKey,
  fetchMe,
  loadX25519Identity,
  ensureRingPrivkey,
  type SessionUser,
} from "../lib/passkey";

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
      setState({
        phase: "error",
        message: e instanceof Error ? e.message : String(e),
      });
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
