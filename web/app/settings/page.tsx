"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { API_URL } from "../lib/resqdCrypto";
import {
  fetchMe,
  loadMasterKey,
  bytesToB64u,
  type SessionUser,
} from "../lib/passkey";
import { exportRecoveryKit, type ExportProgress } from "../lib/recoveryKit";

interface TokenSummary {
  token_hash: string;
  label: string;
  created_at: number;
  last_used_at?: number | null;
}

interface ListTokensResponse {
  count: number;
  tokens: TokenSummary[];
}

interface CreateTokenResponse {
  token: string;
  token_hash: string;
  label: string;
  created_at: number;
}

function formatTimestamp(secs: number): string {
  if (!secs) return "—";
  return new Date(secs * 1000).toLocaleString();
}

export default function SettingsPage() {
  const [user, setUser] = useState<SessionUser | null>(null);
  const [tokens, setTokens] = useState<TokenSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [newTokenLabel, setNewTokenLabel] = useState("MCP (Claude)");
  const [creating, setCreating] = useState(false);
  const [justCreated, setJustCreated] = useState<CreateTokenResponse | null>(null);
  const [masterKeyB64, setMasterKeyB64] = useState<string | null>(null);
  const [keyVisible, setKeyVisible] = useState(false);
  const [kitProgress, setKitProgress] = useState<ExportProgress | null>(null);
  const [kitBusy, setKitBusy] = useState(false);

  const onExportKit = async () => {
    setKitBusy(true);
    setKitProgress({ phase: "init" });
    try {
      await exportRecoveryKit((p) => setKitProgress(p));
    } finally {
      setKitBusy(false);
    }
  };

  useEffect(() => {
    (async () => {
      const me = await fetchMe();
      if (!me) {
        window.location.href = "/login/";
        return;
      }
      setUser(me);
      const mk = loadMasterKey();
      if (mk) setMasterKeyB64(bytesToB64u(mk));
      await refreshTokens();
      setLoading(false);
    })();
  }, []);

  const refreshTokens = async () => {
    try {
      const r = await fetch(`${API_URL}/auth/tokens`, { credentials: "include" });
      if (!r.ok) throw new Error(`${r.status} ${await r.text()}`);
      const data: ListTokensResponse = await r.json();
      setTokens(data.tokens.sort((a, b) => b.created_at - a.created_at));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  const createToken = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreating(true);
    setError(null);
    try {
      const r = await fetch(`${API_URL}/auth/tokens`, {
        method: "POST",
        credentials: "include",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ label: newTokenLabel || "unnamed" }),
      });
      if (!r.ok) throw new Error(`${r.status} ${await r.text()}`);
      const data: CreateTokenResponse = await r.json();
      setJustCreated(data);
      await refreshTokens();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setCreating(false);
    }
  };

  const revoke = async (hash: string, label: string) => {
    if (!window.confirm(`Revoke token "${label}"? Any MCP client using it will stop working.`)) {
      return;
    }
    try {
      const r = await fetch(
        `${API_URL}/auth/tokens/${encodeURIComponent(hash)}`,
        { method: "DELETE", credentials: "include" },
      );
      if (!r.ok) throw new Error(`${r.status} ${await r.text()}`);
      setTokens((t) => t.filter((x) => x.token_hash !== hash));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  const copy = (text: string) => {
    navigator.clipboard.writeText(text).catch(() => {});
  };

  const mcpConfig = (token: string, masterKey: string | null) =>
    JSON.stringify(
      {
        mcpServers: {
          resqd: {
            command: "resqd-mcp",
            env: {
              RESQD_API_URL: API_URL,
              RESQD_API_TOKEN: token,
              ...(masterKey ? { RESQD_MASTER_KEY_B64: masterKey } : {}),
            },
          },
        },
      },
      null,
      2,
    );

  if (loading) {
    return (
      <main className="mx-auto max-w-3xl px-6 py-16 text-slate-100">
        <p className="text-slate-400 text-sm">Loading…</p>
      </main>
    );
  }

  return (
    <main className="mx-auto max-w-3xl px-6 py-12 text-slate-100">
      <header className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-3xl font-bold">Settings</h1>
          {user && (
            <p className="text-xs text-slate-500 mt-1">
              Signed in as <span className="text-slate-300">{user.email}</span>
            </p>
          )}
        </div>
        <Link
          href="/vault/"
          className="text-xs text-amber-400 hover:underline"
        >
          ← Back to vault
        </Link>
      </header>

      {error && (
        <div className="mb-6 bg-red-950/40 border border-red-900 rounded-lg p-3 text-sm text-red-300">
          {error}
        </div>
      )}

      {/* ─────────────── API tokens ─────────────── */}

      <section className="mb-10">
        <h2 className="text-xl font-semibold mb-1">API tokens</h2>
        <p className="text-xs text-slate-500 mb-4">
          Long-lived bearer tokens for scripting and MCP clients. Each
          token has the same permissions as your passkey session. Keep
          them secret — anyone who holds one can read, write, and delete
          your vault.
        </p>

        <form
          onSubmit={createToken}
          className="flex gap-2 mb-4 bg-slate-900 border border-slate-800 rounded-lg p-3"
        >
          <input
            type="text"
            value={newTokenLabel}
            onChange={(e) => setNewTokenLabel(e.target.value)}
            placeholder="Label (e.g. Claude MCP, CLI)"
            className="flex-1 bg-slate-950 border border-slate-800 rounded px-3 py-2 text-sm"
            disabled={creating}
          />
          <button
            type="submit"
            disabled={creating || !newTokenLabel}
            className="rounded bg-amber-500 text-slate-900 font-semibold px-4 py-2 text-sm disabled:opacity-30"
          >
            {creating ? "Creating…" : "Mint token"}
          </button>
        </form>

        {justCreated && (
          <div className="mb-4 bg-green-950/40 border border-green-900 rounded-lg p-4 space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold text-green-400">
                ✓ Token created — copy it now
              </h3>
              <button
                onClick={() => setJustCreated(null)}
                className="text-xs text-slate-500 hover:text-slate-300"
              >
                Dismiss
              </button>
            </div>
            <p className="text-xs text-slate-400">
              This is the only time you'll see the full token. If you
              lose it, revoke it here and mint a new one.
            </p>
            <div className="bg-slate-950 border border-slate-800 rounded p-3">
              <code className="block text-xs font-mono text-amber-300 break-all">
                {justCreated.token}
              </code>
              <button
                onClick={() => copy(justCreated.token)}
                className="mt-2 text-xs text-amber-400 hover:underline"
              >
                Copy token
              </button>
            </div>
            <details className="bg-slate-950 border border-slate-800 rounded p-3">
              <summary className="text-xs text-slate-400 cursor-pointer">
                Drop-in Claude Desktop / Claude Code config
              </summary>
              <pre className="mt-2 text-xs font-mono text-slate-300 overflow-x-auto whitespace-pre-wrap">
                {mcpConfig(justCreated.token, masterKeyB64)}
              </pre>
              <button
                onClick={() => copy(mcpConfig(justCreated.token, masterKeyB64))}
                className="mt-2 text-xs text-amber-400 hover:underline"
              >
                Copy config
              </button>
            </details>
          </div>
        )}

        {tokens.length === 0 ? (
          <p className="text-xs text-slate-500 italic">
            No tokens yet.
          </p>
        ) : (
          <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
            <table className="w-full text-sm">
              <thead className="bg-slate-950 text-slate-400 text-xs uppercase">
                <tr>
                  <th className="text-left py-2 px-4 font-medium">Label</th>
                  <th className="text-left py-2 px-4 font-medium">Created</th>
                  <th className="text-right py-2 px-4 font-medium"></th>
                </tr>
              </thead>
              <tbody>
                {tokens.map((t) => (
                  <tr
                    key={t.token_hash}
                    className="border-t border-slate-800"
                  >
                    <td className="py-3 px-4">
                      <div className="text-slate-100">{t.label}</div>
                      <div className="text-xs text-slate-500 font-mono">
                        {t.token_hash.slice(0, 12)}…
                      </div>
                    </td>
                    <td className="py-3 px-4 text-xs text-slate-400">
                      {formatTimestamp(t.created_at)}
                    </td>
                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={() => revoke(t.token_hash, t.label)}
                        className="text-xs text-slate-500 hover:text-red-400"
                      >
                        Revoke
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* ─────────────── Master key export ─────────────── */}

      <section>
        <h2 className="text-xl font-semibold mb-1">Master key export</h2>
        <p className="text-xs text-slate-500 mb-4">
          Your vault master key, derived from your passkey via the
          WebAuthn PRF extension. It never leaves the browser on its
          own — but if you want an MCP server or CLI to decrypt your
          vault locally, it needs this key. Paste it into the client's
          env as <code className="text-slate-400">RESQD_MASTER_KEY_B64</code>.
          Treat it like a root password: anyone who has it can read
          everything.
        </p>

        {masterKeyB64 ? (
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs uppercase text-slate-500 tracking-wide">
                RESQD_MASTER_KEY_B64 (base64url)
              </span>
              <button
                onClick={() => setKeyVisible(!keyVisible)}
                className="text-xs text-slate-400 hover:text-slate-200"
              >
                {keyVisible ? "Hide" : "Reveal"}
              </button>
            </div>
            <code className="block bg-slate-950 border border-slate-800 rounded p-3 text-xs font-mono text-amber-300 break-all">
              {keyVisible ? masterKeyB64 : "•".repeat(masterKeyB64.length)}
            </code>
            <button
              onClick={() => copy(masterKeyB64)}
              className="text-xs text-amber-400 hover:underline"
            >
              Copy master key
            </button>
          </div>
        ) : (
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 text-sm text-slate-400">
            Master key not in memory.{" "}
            <Link href="/login/" className="text-amber-400 hover:underline">
              Sign in again
            </Link>{" "}
            to re-derive it from your passkey.
          </div>
        )}
      </section>

      {/* ─────────────── Recovery Kit ─────────────── */}

      <section className="mt-10">
        <h2 className="text-xl font-semibold mb-1">
          Recovery Kit — data of last resort
        </h2>
        <p className="text-xs text-slate-500 mb-4 leading-relaxed">
          The guarantee nobody else makes: even if RESQD itself
          disappears — servers gone, domain lapsed, business dead — you
          can still get your data back. Download a Recovery Kit and
          store it somewhere safe (encrypted external drive, safe
          deposit box, printed QR bundle, whatever you trust). Feed
          it to the open-source{" "}
          <code className="text-slate-300">resqd-recover</code> CLI and
          every file is reconstructed on your own machine with zero
          dependency on us.
        </p>
        <p className="text-xs text-slate-500 mb-4 leading-relaxed">
          The kit is a single JSON file containing your master key,
          long-term identity, every file&apos;s unwrapped per-asset
          key, and the raw ciphertext shards. It also includes files
          people have <span className="text-slate-300">shared with you</span> —
          if the sender later unshares, or if either of you loses your
          accounts, the snapshot you downloaded today still decrypts.
        </p>
        <div className="bg-amber-950/30 border border-amber-900 rounded-lg p-3 mb-4 text-xs text-amber-300 leading-relaxed">
          ⚠ The kit contains your master key in plaintext. Treat it like
          a printed passphrase — encrypt it, store it offline, don&apos;t
          email it to yourself. Anyone with the kit can read every file
          in it.
        </div>

        <button
          onClick={onExportKit}
          disabled={kitBusy || !masterKeyB64}
          className="rounded-lg bg-violet-500 text-slate-50 font-semibold px-5 py-2.5 text-sm disabled:opacity-30"
        >
          {kitBusy ? "Building Recovery Kit…" : "Download Recovery Kit"}
        </button>

        {kitProgress && (
          <div className="mt-4 bg-slate-900 border border-slate-800 rounded-lg p-3 text-xs text-slate-300 font-mono">
            {kitProgress.phase === "init" && "Initializing…"}
            {kitProgress.phase === "listing" && "Listing vault…"}
            {kitProgress.phase === "asset" && (
              <>
                Exporting asset {kitProgress.current}/{kitProgress.total}:{" "}
                <span className="text-slate-500">{kitProgress.label?.slice(0, 16)}…</span>
              </>
            )}
            {kitProgress.phase === "shard" && (
              <>
                Downloading shards — {kitProgress.label}
              </>
            )}
            {kitProgress.phase === "finalizing" && "Finalizing kit…"}
            {kitProgress.phase === "done" && (
              <span className="text-green-400">
                ✓ Recovery Kit downloaded ({kitProgress.total} assets)
              </span>
            )}
            {kitProgress.phase === "error" && (
              <span className="text-red-400">Error: {kitProgress.error}</span>
            )}
          </div>
        )}

        <details className="mt-4 bg-slate-900 border border-slate-800 rounded-lg p-3 text-xs text-slate-400">
          <summary className="cursor-pointer text-slate-300">
            What&apos;s inside the kit?
          </summary>
          <ul className="mt-2 space-y-1 list-disc list-inside leading-relaxed">
            <li>Your user id, email, and the PRF-derived vault master key</li>
            <li>
              Your long-term X25519 identity (both halves — lets you decrypt
              files people shared with you)
            </li>
            <li>
              Every asset you own or have been shared, with its unwrapped
              per-asset XChaCha20 key and all six Reed-Solomon ciphertext
              shards
            </li>
            <li>
              The file format spec version and a URL to the
              <code className="mx-1 text-slate-300">resqd-recover</code>
              CLI source
            </li>
            <li>
              Links to three recovery paths: DIY (free, open-source tool),
              concierge (paid, coming), and heir claim (paid, coming, for
              posthumous access)
            </li>
          </ul>
        </details>
      </section>
    </main>
  );
}
