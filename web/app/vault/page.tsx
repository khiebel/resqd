"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { API_URL, base64ToBytes, getCrypto } from "../lib/resqdCrypto";
import {
  fetchMe,
  loadMasterKey,
  loadX25519Identity,
  logout,
  type SessionUser,
} from "../lib/passkey";

interface VaultAsset {
  asset_id: string;
  created_at: number;
  encrypted_meta_b64?: string | null;
  /** "owner" or "sharee". Defaults to "owner" on legacy rows. */
  role?: "owner" | "sharee";
  /** For sharees: who shared it with us. */
  shared_by_email?: string | null;
  /** For sharees: sender's X25519 public identity. */
  sender_pubkey_x25519_b64?: string | null;
  /** Populated client-side after decrypting `encrypted_meta_b64`. */
  name?: string | null;
  mime?: string | null;
}

interface VaultListResponse {
  user_id: string;
  count: number;
  assets: VaultAsset[];
}

type ViewState =
  | { phase: "loading" }
  | { phase: "ready"; assets: VaultAsset[] }
  | { phase: "error"; message: string };

function StorageBar({ used, cap }: { used: number; cap: number }) {
  const pct = cap > 0 ? Math.min(100, (used / cap) * 100) : 0;
  const warn = pct >= 80;
  const full = pct >= 100;
  return (
    <section className="mb-8 bg-slate-900 border border-slate-800 rounded-lg p-4">
      <div className="flex items-center justify-between text-xs mb-2">
        <span className="text-slate-400">
          {formatBytes(used)} of {formatBytes(cap)} used
        </span>
        <span className={full ? "text-red-400" : warn ? "text-amber-400" : "text-slate-500"}>
          {pct.toFixed(0)}%
        </span>
      </div>
      <div className="h-2 bg-slate-950 rounded-full overflow-hidden">
        <div
          className={`h-full rounded-full transition-all ${
            full
              ? "bg-red-500"
              : warn
                ? "bg-amber-500"
                : "bg-gradient-to-r from-amber-400 to-violet-500"
          }`}
          style={{ width: `${pct}%` }}
        />
      </div>
      {full && (
        <p className="mt-2 text-xs text-red-300">
          Vault is full. Delete something to make room before uploading more.
        </p>
      )}
      {!full && warn && (
        <p className="mt-2 text-xs text-amber-300">
          You&apos;re close to your alpha quota. This is a hard cap during
          the alpha — more capacity comes with paid tiers.
        </p>
      )}
    </section>
  );
}

async function deleteAsset(assetId: string): Promise<void> {
  const resp = await fetch(`${API_URL}/vault/${encodeURIComponent(assetId)}`, {
    method: "DELETE",
    credentials: "include",
  });
  if (!resp.ok) {
    throw new Error(`delete failed: ${resp.status} ${await resp.text()}`);
  }
}

interface UserLookupResponse {
  user_id: string;
  email: string;
  display_name: string;
  pubkey_x25519_b64: string;
}

interface ShareSummary {
  recipient_user_id: string;
  recipient_email: string;
  created_at: number;
}

/**
 * Run the full client-side share ceremony for an asset the caller owns:
 *
 * 1. Look up the recipient's pubkey.
 * 2. Fetch the asset manifest and unwrap the per-asset key under the
 *    caller's master key.
 * 3. Derive the (sender, recipient, asset) ECDH wrap key in WASM.
 * 4. Re-seal the per-asset key and the filename hint under that wrap key.
 * 5. POST the sealed bundle to `/vault/{id}/shares`.
 *
 * Everything is client-side. The server never sees the per-asset key,
 * the wrap key, or the plaintext filename.
 */
async function shareAsset(
  asset: VaultAsset,
  recipientEmail: string,
): Promise<void> {
  const masterKey = loadMasterKey();
  const ident = loadX25519Identity();
  if (!masterKey) throw new Error("master key not loaded — please log in again");
  if (!ident) {
    throw new Error(
      "your X25519 identity isn't ready yet — log out and back in, then retry",
    );
  }

  const recipientResp = await fetch(
    `${API_URL}/users/lookup?email=${encodeURIComponent(recipientEmail)}`,
    { credentials: "include" },
  );
  if (recipientResp.status === 404) {
    throw new Error(
      `no RESQD user with that email, or they haven't set up sharing yet`,
    );
  }
  if (!recipientResp.ok) {
    throw new Error(`lookup failed: ${recipientResp.status}`);
  }
  const recipient = (await recipientResp.json()) as UserLookupResponse;

  // Fetch the asset manifest to get the wrapped per-asset key + meta.
  // This rotates the canary on the server — fine, shares count as
  // access.
  const fetchResp = await fetch(
    `${API_URL}/vault/${encodeURIComponent(asset.asset_id)}`,
    { credentials: "include" },
  );
  if (!fetchResp.ok) {
    throw new Error(`fetch manifest failed: ${fetchResp.status}`);
  }
  const manifest = (await fetchResp.json()) as {
    wrapped_key_b64?: string;
    encrypted_meta_b64?: string;
    role?: string;
  };
  if (manifest.role && manifest.role !== "owner") {
    throw new Error("you can only share assets you own");
  }
  if (!manifest.wrapped_key_b64) {
    throw new Error("this asset has no wrapped key — cannot share");
  }

  const crypto = await getCrypto();

  // Unwrap per-asset key under master key.
  const wrappedAssetKeyJson = atob(manifest.wrapped_key_b64);
  const assetKey = crypto.decrypt_data(masterKey, wrappedAssetKeyJson);

  // Derive ECDH wrap key bound to (this sender, recipient, asset_id).
  const wrapKeyB64 = crypto.x25519_sender_wrap_key(
    ident.privB64,
    recipient.pubkey_x25519_b64,
    asset.asset_id,
  );
  const wrapKey = base64ToBytes(wrapKeyB64);

  // Re-seal the per-asset key under the wrap key.
  const wrappedForRecipientJson = crypto.encrypt_data(wrapKey, assetKey);
  const wrappedForRecipientB64 = btoa(wrappedForRecipientJson);

  // Re-seal the filename hint under the SAME wrap key, if present.
  // Optional — sender may have a nameless asset.
  let metaForRecipientB64: string | null = null;
  if (manifest.encrypted_meta_b64) {
    try {
      const encMetaJson = atob(manifest.encrypted_meta_b64);
      const metaBytes = crypto.decrypt_data(masterKey, encMetaJson);
      const reSealedJson = crypto.encrypt_data(wrapKey, metaBytes);
      metaForRecipientB64 = btoa(reSealedJson);
    } catch (e) {
      console.warn(
        "could not re-encrypt meta for sharee — filename hint omitted:",
        e,
      );
    }
  }

  const postResp = await fetch(
    `${API_URL}/vault/${encodeURIComponent(asset.asset_id)}/shares`,
    {
      method: "POST",
      credentials: "include",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        recipient_email: recipient.email,
        sender_pubkey_x25519_b64: ident.pubB64,
        wrapped_key_for_recipient_b64: wrappedForRecipientB64,
        encrypted_meta_for_recipient_b64: metaForRecipientB64,
      }),
    },
  );
  if (!postResp.ok) {
    throw new Error(`share failed: ${postResp.status} ${await postResp.text()}`);
  }
}

async function listShares(assetId: string): Promise<ShareSummary[]> {
  const resp = await fetch(
    `${API_URL}/vault/${encodeURIComponent(assetId)}/shares`,
    { credentials: "include" },
  );
  if (!resp.ok) return [];
  const data = (await resp.json()) as { shares: ShareSummary[] };
  return data.shares;
}

async function revokeShare(
  assetId: string,
  recipientEmail: string,
): Promise<void> {
  const resp = await fetch(
    `${API_URL}/vault/${encodeURIComponent(assetId)}/shares/${encodeURIComponent(recipientEmail)}`,
    { method: "DELETE", credentials: "include" },
  );
  if (!resp.ok) {
    throw new Error(`revoke failed: ${resp.status}`);
  }
}


function formatTimestamp(secs: number): string {
  if (!secs) return "—";
  const d = new Date(secs * 1000);
  return d.toLocaleString();
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

function ShareDialogModal({
  state,
  email,
  setEmail,
  existingShares,
  onSubmit,
  onRevoke,
  onClose,
}: {
  state: ShareDialogState;
  email: string;
  setEmail: (s: string) => void;
  existingShares: ShareSummary[];
  onSubmit: () => void | Promise<void>;
  onRevoke: (recipientEmail: string) => void | Promise<void>;
  onClose: () => void;
}) {
  if (state.phase === "closed") return null;
  const asset =
    state.phase === "open" ||
    state.phase === "submitting" ||
    state.phase === "error" ||
    state.phase === "done"
      ? state.asset
      : null;
  if (!asset) return null;
  const busy = state.phase === "submitting";

  return (
    <div
      className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-md w-full p-6 text-slate-100">
        <h3 className="text-lg font-semibold mb-1">
          Share {asset.name ?? `asset ${asset.asset_id.slice(0, 8)}…`}
        </h3>
        <p className="text-xs text-slate-500 mb-4">
          Recipients can <span className="text-slate-300">view and download</span>
          {" "}this file. They cannot modify, delete, or re-share it. Revoking
          stops future reads but cannot un-read what they&apos;ve already
          fetched.
        </p>

        {state.phase === "done" ? (
          <div className="mb-4 p-3 rounded bg-green-900/30 border border-green-800 text-sm text-green-300">
            ✓ Shared with{" "}
            <span className="font-mono">{state.email}</span>
          </div>
        ) : null}

        {state.phase === "error" ? (
          <div className="mb-4 p-3 rounded bg-red-900/30 border border-red-800 text-sm text-red-300">
            {state.message}
          </div>
        ) : null}

        <label className="block text-xs font-medium text-slate-400 uppercase tracking-wide mb-1">
          Recipient email
        </label>
        <input
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          placeholder="person@example.com"
          disabled={busy}
          className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-sm mb-3"
        />

        <div className="flex gap-2 mb-6">
          <button
            onClick={() => void onSubmit()}
            disabled={busy || !email.trim()}
            className="flex-1 rounded-lg bg-violet-500 text-slate-50 font-semibold px-4 py-2 text-sm disabled:opacity-30"
          >
            {busy ? "Sharing…" : "Share"}
          </button>
          <button
            onClick={onClose}
            disabled={busy}
            className="rounded-lg bg-slate-800 text-slate-300 px-4 py-2 text-sm"
          >
            Close
          </button>
        </div>

        {existingShares.length > 0 && (
          <div className="border-t border-slate-800 pt-4">
            <div className="text-xs font-medium text-slate-400 uppercase tracking-wide mb-2">
              Currently shared with
            </div>
            <ul className="space-y-1">
              {existingShares.map((s) => (
                <li
                  key={s.recipient_user_id}
                  className="flex items-center justify-between text-sm"
                >
                  <span className="text-slate-300 font-mono">
                    {s.recipient_email}
                  </span>
                  <button
                    onClick={() => void onRevoke(s.recipient_email)}
                    className="text-xs text-slate-500 hover:text-red-400"
                  >
                    Revoke
                  </button>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </div>
  );
}

type ShareDialogState =
  | { phase: "closed" }
  | { phase: "open"; asset: VaultAsset }
  | { phase: "submitting"; asset: VaultAsset }
  | { phase: "error"; asset: VaultAsset; message: string }
  | { phase: "done"; asset: VaultAsset; email: string };

export default function VaultPage() {
  const [user, setUser] = useState<SessionUser | null>(null);
  const [view, setView] = useState<ViewState>({ phase: "loading" });
  const [shareDialog, setShareDialog] = useState<ShareDialogState>({
    phase: "closed",
  });
  const [shareEmail, setShareEmail] = useState("");
  const [existingShares, setExistingShares] = useState<ShareSummary[]>([]);

  const openShareFor = useCallback(async (asset: VaultAsset) => {
    setShareDialog({ phase: "open", asset });
    setShareEmail("");
    setExistingShares([]);
    try {
      const shares = await listShares(asset.asset_id);
      setExistingShares(shares);
    } catch (e) {
      console.warn("listShares failed:", e);
    }
  }, []);

  const closeShareDialog = useCallback(() => {
    setShareDialog({ phase: "closed" });
    setShareEmail("");
    setExistingShares([]);
  }, []);

  const submitShare = useCallback(async () => {
    if (shareDialog.phase !== "open") return;
    const asset = shareDialog.asset;
    const email = shareEmail.trim().toLowerCase();
    if (!email.includes("@")) {
      setShareDialog({ phase: "error", asset, message: "enter a valid email" });
      return;
    }
    setShareDialog({ phase: "submitting", asset });
    try {
      await shareAsset(asset, email);
      setShareDialog({ phase: "done", asset, email });
      setShareEmail("");
      // Refresh the share list inline without closing the dialog.
      try {
        setExistingShares(await listShares(asset.asset_id));
      } catch (e) {
        console.warn("listShares refresh failed:", e);
      }
    } catch (e) {
      setShareDialog({
        phase: "error",
        asset,
        message: e instanceof Error ? e.message : String(e),
      });
    }
  }, [shareDialog, shareEmail]);

  const onRevokeShare = useCallback(
    async (recipientEmail: string) => {
      if (
        shareDialog.phase !== "open" &&
        shareDialog.phase !== "error" &&
        shareDialog.phase !== "done"
      )
        return;
      const asset =
        shareDialog.phase === "open"
          ? shareDialog.asset
          : shareDialog.phase === "error"
            ? shareDialog.asset
            : shareDialog.asset;
      try {
        await revokeShare(asset.asset_id, recipientEmail);
        setExistingShares((prev) =>
          prev.filter((s) => s.recipient_email !== recipientEmail),
        );
      } catch (e) {
        console.warn("revoke failed:", e);
      }
    },
    [shareDialog],
  );

  useEffect(() => {
    (async () => {
      const me = await fetchMe();
      if (!me) {
        window.location.href = "/login/";
        return;
      }
      setUser(me);
      try {
        const resp = await fetch(`${API_URL}/vault`, {
          credentials: "include",
        });
        if (!resp.ok) {
          throw new Error(`${resp.status} ${await resp.text()}`);
        }
        const data: VaultListResponse = await resp.json();

        // Decrypt filename hints in-place. Needs the PRF-derived master
        // key (for owned items) AND the X25519 private identity (for
        // sharee items, to re-derive the share wrap key). If either is
        // missing we still render the list with UUIDs.
        const masterKey = loadMasterKey();
        const ident = loadX25519Identity();
        if (masterKey) {
          const crypto = await getCrypto();
          for (const a of data.assets) {
            if (!a.encrypted_meta_b64) continue;
            try {
              let keyForMeta: Uint8Array;
              if (a.role === "sharee") {
                if (!ident || !a.sender_pubkey_x25519_b64) {
                  // Can't derive the wrap key without both halves.
                  continue;
                }
                const wrapB64 = crypto.x25519_recipient_wrap_key(
                  ident.privB64,
                  a.sender_pubkey_x25519_b64,
                  a.asset_id,
                );
                keyForMeta = base64ToBytes(wrapB64);
              } else {
                keyForMeta = masterKey;
              }
              const metaJson = atob(a.encrypted_meta_b64);
              const plaintext = crypto.decrypt_data(keyForMeta, metaJson);
              const parsed = JSON.parse(new TextDecoder().decode(plaintext));
              if (parsed && typeof parsed === "object") {
                a.name = typeof parsed.name === "string" ? parsed.name : null;
                a.mime = typeof parsed.mime === "string" ? parsed.mime : null;
              }
            } catch (e) {
              // Best-effort — a decrypt failure just means the row falls
              // back to showing its UUID. Log it so we notice trends but
              // don't fail the whole page.
              console.warn(`meta decrypt failed for ${a.asset_id}:`, e);
            }
          }
        }
        setView({ phase: "ready", assets: data.assets });
      } catch (e) {
        setView({
          phase: "error",
          message: e instanceof Error ? e.message : String(e),
        });
      }
    })();
  }, []);

  const onLogout = async () => {
    await logout();
    window.location.href = "/login/";
  };

  const onDelete = async (asset: VaultAsset) => {
    const label = asset.name ? `"${asset.name}"` : `asset ${asset.asset_id.slice(0, 8)}…`;
    if (!window.confirm(`Permanently delete ${label}? This cannot be undone.`)) {
      return;
    }
    try {
      await deleteAsset(asset.asset_id);
      // Optimistic remove — no need to refetch the whole list.
      setView((v) =>
        v.phase === "ready"
          ? { phase: "ready", assets: v.assets.filter((a) => a.asset_id !== asset.asset_id) }
          : v,
      );
    } catch (e) {
      setView({
        phase: "error",
        message: e instanceof Error ? e.message : String(e),
      });
    }
  };

  return (
    <main className="mx-auto max-w-3xl px-6 py-12 text-slate-100">
      <header className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-3xl font-bold">My Vault</h1>
          {user && (
            <p className="text-xs text-slate-500 mt-1">
              Signed in as{" "}
              <span className="text-slate-300">{user.email}</span>
            </p>
          )}
        </div>
        <div className="flex items-center gap-4">
          <Link
            href="/upload/"
            className="rounded-lg bg-amber-500 text-slate-900 font-semibold px-4 py-2 text-sm"
          >
            + Upload
          </Link>
          <Link
            href="/mcp/"
            className="text-xs text-slate-400 hover:text-slate-200"
          >
            Connect Claude
          </Link>
          <Link
            href="/settings/"
            className="text-xs text-slate-400 hover:text-slate-200"
          >
            Settings
          </Link>
          <Link
            href="/billing/"
            className="text-xs text-slate-400 hover:text-slate-200"
          >
            Billing
          </Link>
          <button
            onClick={onLogout}
            className="text-xs text-slate-400 hover:text-slate-200"
          >
            Sign out
          </button>
        </div>
      </header>

      {/* Storage usage bar */}
      {user &&
        typeof user.storage_used_bytes === "number" &&
        typeof user.storage_quota_bytes === "number" && (
          <StorageBar
            used={user.storage_used_bytes}
            cap={user.storage_quota_bytes}
          />
        )}

      {view.phase === "loading" && (
        <p className="text-slate-500 text-sm">Loading your vault…</p>
      )}

      {view.phase === "error" && (
        <p className="text-red-400 text-sm">Error: {view.message}</p>
      )}

      {view.phase === "ready" && view.assets.length === 0 && (
        <>
          <section className="border-2 border-dashed border-slate-800 rounded-xl p-12 text-center mb-6">
            <p className="text-slate-400 mb-4">
              Your vault is empty. Upload your first file to see it here.
            </p>
            <Link
              href="/upload/"
              className="inline-block rounded-lg bg-amber-500 text-slate-900 font-semibold px-5 py-2 text-sm"
            >
              Upload something
            </Link>
          </section>

          <section className="bg-gradient-to-br from-amber-500/5 to-violet-500/5 border border-amber-500/20 rounded-xl p-6 flex items-start gap-4">
            <div className="text-3xl shrink-0">🤖</div>
            <div className="flex-1">
              <h3 className="text-lg font-semibold text-slate-100 mb-1">
                Or let Claude do it
              </h3>
              <p className="text-sm text-slate-400 mb-3 leading-relaxed">
                RESQD ships a Model Context Protocol server so you can
                tell Claude &ldquo;upload ~/Documents/tax.pdf to my
                vault&rdquo; and it happens — encrypted locally, sharded
                across six clouds, anchored on chain, the whole stack.
                Zero-knowledge all the way through.
              </p>
              <Link
                href="/mcp/"
                className="inline-block text-sm text-amber-400 hover:underline font-semibold"
              >
                Connect Claude →
              </Link>
            </div>
          </section>
        </>
      )}

      {shareDialog.phase !== "closed" && (
        <ShareDialogModal
          state={shareDialog}
          email={shareEmail}
          setEmail={setShareEmail}
          existingShares={existingShares}
          onSubmit={submitShare}
          onRevoke={onRevokeShare}
          onClose={closeShareDialog}
        />
      )}

      {view.phase === "ready" && view.assets.length > 0 && (
        <section className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-slate-950 text-slate-400 text-xs uppercase">
              <tr>
                <th className="text-left py-2 px-4 font-medium">File</th>
                <th className="text-left py-2 px-4 font-medium">Added</th>
                <th className="text-right py-2 px-4 font-medium"></th>
              </tr>
            </thead>
            <tbody>
              {view.assets.map((a) => {
                const isSharee = a.role === "sharee";
                return (
                  <tr
                    key={`${a.role ?? "owner"}:${a.asset_id}`}
                    className="border-t border-slate-800 hover:bg-slate-800/40"
                  >
                    <td className="py-3 px-4">
                      <div className="flex items-center gap-2">
                        {a.name ? (
                          <div>
                            <div className="text-slate-100">{a.name}</div>
                            <div className="text-xs text-slate-500 font-mono break-all">
                              {a.asset_id.slice(0, 8)}…
                              {a.mime && (
                                <span className="ml-2">· {a.mime}</span>
                              )}
                              {isSharee && a.shared_by_email && (
                                <span className="ml-2 text-violet-300">
                                  · shared by {a.shared_by_email}
                                </span>
                              )}
                            </div>
                          </div>
                        ) : (
                          <div className="font-mono text-xs break-all text-slate-300">
                            {a.asset_id}
                            {isSharee && a.shared_by_email && (
                              <span className="ml-2 text-violet-300">
                                · shared by {a.shared_by_email}
                              </span>
                            )}
                          </div>
                        )}
                        {isSharee && (
                          <span className="shrink-0 text-[10px] uppercase tracking-wider bg-violet-500/20 text-violet-300 px-1.5 py-0.5 rounded">
                            Shared
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="py-3 px-4 text-xs text-slate-400">
                      {formatTimestamp(a.created_at)}
                    </td>
                    <td className="py-3 px-4 text-right whitespace-nowrap">
                      <Link
                        href={`/fetch/?id=${encodeURIComponent(a.asset_id)}`}
                        className="text-amber-400 hover:underline text-xs mr-4"
                      >
                        Open →
                      </Link>
                      {!isSharee && (
                        <>
                          <button
                            onClick={() => openShareFor(a)}
                            className="text-xs text-slate-400 hover:text-violet-300 mr-4"
                            aria-label="Share asset"
                          >
                            Share
                          </button>
                          <button
                            onClick={() => onDelete(a)}
                            className="text-xs text-slate-500 hover:text-red-400"
                            aria-label="Delete asset"
                          >
                            Delete
                          </button>
                        </>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </section>
      )}
    </main>
  );
}
