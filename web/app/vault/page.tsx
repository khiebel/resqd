"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { API_URL, getCrypto } from "../lib/resqdCrypto";
import { fetchMe, loadMasterKey, logout, type SessionUser } from "../lib/passkey";

interface VaultAsset {
  asset_id: string;
  created_at: number;
  encrypted_meta_b64?: string | null;
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

async function deleteAsset(assetId: string): Promise<void> {
  const resp = await fetch(`${API_URL}/vault/${encodeURIComponent(assetId)}`, {
    method: "DELETE",
    credentials: "include",
  });
  if (!resp.ok) {
    throw new Error(`delete failed: ${resp.status} ${await resp.text()}`);
  }
}

function formatTimestamp(secs: number): string {
  if (!secs) return "—";
  const d = new Date(secs * 1000);
  return d.toLocaleString();
}

export default function VaultPage() {
  const [user, setUser] = useState<SessionUser | null>(null);
  const [view, setView] = useState<ViewState>({ phase: "loading" });

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
        // key, which lives in sessionStorage. If it's missing (e.g., the
        // user has a valid session cookie but a fresh tab where the PRF
        // output was never cached), we still render the list with UUIDs
        // and let the user re-login to unlock names.
        const masterKey = loadMasterKey();
        if (masterKey) {
          const crypto = await getCrypto();
          for (const a of data.assets) {
            if (!a.encrypted_meta_b64) continue;
            try {
              const metaJson = atob(a.encrypted_meta_b64);
              const plaintext = crypto.decrypt_data(masterKey, metaJson);
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
      <header className="flex items-center justify-between mb-8">
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
            href="/settings/"
            className="text-xs text-slate-400 hover:text-slate-200"
          >
            Settings
          </Link>
          <button
            onClick={onLogout}
            className="text-xs text-slate-400 hover:text-slate-200"
          >
            Sign out
          </button>
        </div>
      </header>

      {view.phase === "loading" && (
        <p className="text-slate-500 text-sm">Loading your vault…</p>
      )}

      {view.phase === "error" && (
        <p className="text-red-400 text-sm">Error: {view.message}</p>
      )}

      {view.phase === "ready" && view.assets.length === 0 && (
        <section className="border-2 border-dashed border-slate-800 rounded-xl p-12 text-center">
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
              {view.assets.map((a) => (
                <tr
                  key={a.asset_id}
                  className="border-t border-slate-800 hover:bg-slate-800/40"
                >
                  <td className="py-3 px-4">
                    {a.name ? (
                      <>
                        <div className="text-slate-100">{a.name}</div>
                        <div className="text-xs text-slate-500 font-mono break-all">
                          {a.asset_id.slice(0, 8)}…
                          {a.mime && (
                            <span className="ml-2">· {a.mime}</span>
                          )}
                        </div>
                      </>
                    ) : (
                      <div className="font-mono text-xs break-all text-slate-300">
                        {a.asset_id}
                      </div>
                    )}
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
                    <button
                      onClick={() => onDelete(a)}
                      className="text-xs text-slate-500 hover:text-red-400"
                      aria-label="Delete asset"
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}
    </main>
  );
}
