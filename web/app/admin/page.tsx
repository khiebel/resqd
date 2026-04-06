"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { API_URL } from "../lib/resqdCrypto";
import { fetchMe } from "../lib/passkey";

// ── Types ───────────────────────────────────────────────────────────

interface AdminUser {
  email: string;
  user_id: string;
  display_name: string;
  created_at: number;
  storage_used_bytes: number;
  has_x25519_identity: boolean;
}

interface AdminRing {
  ring_id: string;
  name: string;
  owner_user_id: string;
  created_at: number;
  member_count: number;
  has_estate_trigger: boolean;
  estate_trigger_type: string | null;
  last_owner_activity_at: number | null;
}

interface AdminStats {
  user_count: number;
  total_storage_bytes: number;
  ring_count: number;
  total_ring_members: number;
  rings_with_triggers: number;
}

type Tab = "stats" | "users" | "rings";

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

function formatTimestamp(secs: number): string {
  if (!secs) return "—";
  return new Date(secs * 1000).toLocaleString();
}

function timeAgo(secs: number): string {
  if (!secs) return "never";
  const diff = Math.floor(Date.now() / 1000) - secs;
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

// ── Stat card ───────────────────────────────────────────────────────

function StatCard({
  label,
  value,
  sub,
}: {
  label: string;
  value: string | number;
  sub?: string;
}) {
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
      <div className="text-xs text-slate-500 uppercase tracking-wider mb-1">
        {label}
      </div>
      <div className="text-2xl font-bold text-slate-100">{value}</div>
      {sub && <div className="text-xs text-slate-400 mt-1">{sub}</div>}
    </div>
  );
}

// ── Main ────────────────────────────────────────────────────────────

export default function AdminPage() {
  const [tab, setTab] = useState<Tab>("stats");
  const [stats, setStats] = useState<AdminStats | null>(null);
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [rings, setRings] = useState<AdminRing[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchAdmin = useCallback(async (path: string) => {
    const resp = await fetch(`${API_URL}${path}`, {
      credentials: "include",
    });
    if (resp.status === 403) {
      throw new Error("admin access denied — your email is not in the admin list");
    }
    if (resp.status === 401) {
      throw new Error("unauthorized — admin endpoints require CF Access authentication");
    }
    if (!resp.ok) {
      throw new Error(`${resp.status} ${await resp.text()}`);
    }
    return resp.json();
  }, []);

  useEffect(() => {
    (async () => {
      // Admin needs a passkey session (the API uses it to verify
      // the admin email). If no session exists, show a sign-in
      // prompt instead of fetching and getting 401.
      const me = await fetchMe();
      if (!me) {
        setError(
          "Sign in with your passkey first, then come back here. " +
          "The admin console uses your passkey session to verify admin access."
        );
        setLoading(false);
        return;
      }
      try {
        const [s, u, r] = await Promise.all([
          fetchAdmin("/admin/stats"),
          fetchAdmin("/admin/users"),
          fetchAdmin("/admin/rings"),
        ]);
        setStats(s);
        setUsers(u.users);
        setRings(r.rings);
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      } finally {
        setLoading(false);
      }
    })();
  }, [fetchAdmin]);

  if (loading) {
    return (
      <main className="mx-auto max-w-5xl px-6 py-16 text-slate-100">
        <p className="text-slate-400">Loading admin console…</p>
      </main>
    );
  }

  if (error) {
    return (
      <main className="mx-auto max-w-5xl px-6 py-16 text-slate-100">
        <h1 className="text-3xl font-bold mb-4">Admin Console</h1>
        <p className="text-red-400 mb-4">{error}</p>
        <div className="flex gap-4">
          <Link href="/login/" className="text-amber-400 text-sm hover:underline">
            Sign in →
          </Link>
          <Link href="/vault/" className="text-slate-400 text-sm hover:underline">
            ← Back to vault
          </Link>
        </div>
      </main>
    );
  }

  return (
    <main className="mx-auto max-w-5xl px-6 py-12 text-slate-100">
      <header className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-3xl font-bold">Admin Console</h1>
          <p className="text-xs text-slate-500 mt-1">
            RESQD control plane
          </p>
        </div>
        <Link
          href="/vault/"
          className="text-xs text-amber-400 hover:underline"
        >
          ← Back to vault
        </Link>
      </header>

      {/* Tab bar */}
      <div className="flex gap-1 mb-8 bg-slate-900 border border-slate-800 rounded-lg p-1 w-fit">
        {(["stats", "users", "rings"] as Tab[]).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-4 py-1.5 rounded text-sm font-medium transition-colors ${
              tab === t
                ? "bg-violet-500 text-white"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            {t === "stats" ? "Overview" : t === "users" ? "Users" : "Rings"}
          </button>
        ))}
      </div>

      {/* ──── Overview tab ──── */}
      {tab === "stats" && stats && (
        <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
          <StatCard label="Users" value={stats.user_count} />
          <StatCard
            label="Total storage"
            value={formatBytes(stats.total_storage_bytes)}
            sub={`across ${stats.user_count} user(s)`}
          />
          <StatCard label="Rings" value={stats.ring_count} />
          <StatCard
            label="Ring members"
            value={stats.total_ring_members}
            sub={`across ${stats.ring_count} ring(s)`}
          />
          <StatCard
            label="Estate triggers"
            value={stats.rings_with_triggers}
            sub={`of ${stats.ring_count} ring(s)`}
          />
          <StatCard
            label="API status"
            value="Live"
            sub="api.resqd.ai"
          />
        </div>
      )}

      {/* ──── Users tab ──── */}
      {tab === "users" && (
        <section className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-slate-950 text-slate-400 text-xs uppercase">
              <tr>
                <th className="text-left py-2 px-4 font-medium">Email</th>
                <th className="text-left py-2 px-4 font-medium">Storage</th>
                <th className="text-left py-2 px-4 font-medium">Identity</th>
                <th className="text-left py-2 px-4 font-medium">Joined</th>
              </tr>
            </thead>
            <tbody>
              {users.map((u) => (
                <tr
                  key={u.user_id}
                  className="border-t border-slate-800 hover:bg-slate-800/40"
                >
                  <td className="py-3 px-4">
                    <div className="text-slate-100">{u.email}</div>
                    <div className="text-xs text-slate-500 font-mono">
                      {u.user_id.slice(0, 12)}…
                    </div>
                  </td>
                  <td className="py-3 px-4 text-xs text-slate-300">
                    {formatBytes(u.storage_used_bytes)}
                  </td>
                  <td className="py-3 px-4">
                    {u.has_x25519_identity ? (
                      <span className="text-[10px] uppercase tracking-wider bg-green-500/20 text-green-300 px-1.5 py-0.5 rounded">
                        X25519
                      </span>
                    ) : (
                      <span className="text-[10px] uppercase tracking-wider bg-slate-700 text-slate-400 px-1.5 py-0.5 rounded">
                        None
                      </span>
                    )}
                  </td>
                  <td className="py-3 px-4 text-xs text-slate-400">
                    {formatTimestamp(u.created_at)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}

      {/* ──── Rings tab ──── */}
      {tab === "rings" && (
        <section className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
          {rings.length === 0 ? (
            <div className="p-6 text-sm text-slate-400">No rings yet.</div>
          ) : (
            <table className="w-full text-sm">
              <thead className="bg-slate-950 text-slate-400 text-xs uppercase">
                <tr>
                  <th className="text-left py-2 px-4 font-medium">Ring</th>
                  <th className="text-left py-2 px-4 font-medium">Members</th>
                  <th className="text-left py-2 px-4 font-medium">
                    Estate trigger
                  </th>
                  <th className="text-left py-2 px-4 font-medium">
                    Last owner activity
                  </th>
                  <th className="text-left py-2 px-4 font-medium">Created</th>
                </tr>
              </thead>
              <tbody>
                {rings.map((r) => (
                  <tr
                    key={r.ring_id}
                    className="border-t border-slate-800 hover:bg-slate-800/40"
                  >
                    <td className="py-3 px-4">
                      <div className="text-slate-100">{r.name}</div>
                      <div className="text-xs text-slate-500 font-mono">
                        {r.ring_id.slice(0, 12)}…
                      </div>
                    </td>
                    <td className="py-3 px-4 text-xs text-slate-300">
                      {r.member_count}
                    </td>
                    <td className="py-3 px-4">
                      {r.has_estate_trigger ? (
                        <span className="text-[10px] uppercase tracking-wider bg-violet-500/20 text-violet-300 px-1.5 py-0.5 rounded">
                          {r.estate_trigger_type ?? "active"}
                        </span>
                      ) : (
                        <span className="text-xs text-slate-500">—</span>
                      )}
                    </td>
                    <td className="py-3 px-4 text-xs text-slate-400">
                      {r.last_owner_activity_at
                        ? timeAgo(r.last_owner_activity_at)
                        : "—"}
                    </td>
                    <td className="py-3 px-4 text-xs text-slate-400">
                      {formatTimestamp(r.created_at)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>
      )}
    </main>
  );
}
