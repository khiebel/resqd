"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { API_URL } from "../lib/resqdCrypto";

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

interface AdminRingMember {
  user_id: string;
  email: string;
  role: string;
  invited_at: number;
}

interface AdminRingDetail {
  ring_id: string;
  name: string;
  members: AdminRingMember[];
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
  const [selectedRing, setSelectedRing] = useState<AdminRingDetail | null>(null);
  const [unlocking, setUnlocking] = useState(false);
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

  const viewRingMembers = useCallback(async (ringId: string) => {
    try {
      // Uses the regular ring detail endpoint (admin has a passkey session)
      const data = await fetchAdmin(`/rings/${encodeURIComponent(ringId)}`);
      setSelectedRing(data);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, [fetchAdmin]);

  const unlockExecutor = useCallback(async (ringId: string, executorEmail: string) => {
    if (!confirm(`Unlock executor ${executorEmail} on this ring? This grants them full read access to all ring assets. Only do this after verifying proof of death.`)) return;
    setUnlocking(true);
    try {
      const resp = await fetch(
        `${API_URL}/admin/rings/${encodeURIComponent(ringId)}/unlock-executor/${encodeURIComponent(executorEmail)}`,
        { method: "POST", credentials: "include" },
      );
      if (!resp.ok) throw new Error(await resp.text());
      const result = await resp.json();
      setError(null);
      alert(result.message || "Executor unlocked");
      // Refresh the ring detail
      await viewRingMembers(ringId);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setUnlocking(false);
    }
  }, [viewRingMembers]);

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
        <Link href="/vault/" className="text-slate-400 text-sm hover:underline">
          ← Back to vault
        </Link>
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
                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={() => viewRingMembers(r.ring_id)}
                        className="text-xs text-amber-400 hover:underline"
                      >
                        Members →
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}

          {/* Ring member detail + executor unlock */}
          {selectedRing && (
            <div className="mt-6 bg-slate-950 border border-slate-800 rounded-xl p-5">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold">{selectedRing.name} — Members</h3>
                <button
                  onClick={() => setSelectedRing(null)}
                  className="text-xs text-slate-500 hover:text-slate-300"
                >
                  Close
                </button>
              </div>
              <table className="w-full text-sm">
                <thead className="text-slate-400 text-xs uppercase">
                  <tr>
                    <th className="text-left py-2 font-medium">Email</th>
                    <th className="text-left py-2 font-medium">Role</th>
                    <th className="text-left py-2 font-medium">Joined</th>
                    <th className="text-right py-2 font-medium">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {selectedRing.members.map((m) => (
                    <tr key={m.user_id} className="border-t border-slate-800">
                      <td className="py-2 text-slate-300 font-mono text-xs">{m.email}</td>
                      <td className="py-2">
                        <span className={`text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded ${
                          m.role === "executor"
                            ? "bg-red-500/20 text-red-300"
                            : "bg-violet-500/20 text-violet-300"
                        }`}>
                          {m.role}
                        </span>
                      </td>
                      <td className="py-2 text-xs text-slate-400">{formatTimestamp(m.invited_at)}</td>
                      <td className="py-2 text-right">
                        {m.role === "executor" && (
                          <button
                            onClick={() => unlockExecutor(selectedRing.ring_id, m.email)}
                            disabled={unlocking}
                            className="rounded bg-red-600 text-white text-xs font-semibold px-3 py-1 hover:bg-red-500 disabled:opacity-30"
                          >
                            {unlocking ? "Unlocking…" : "Unlock (proof of death)"}
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <p className="mt-3 text-xs text-slate-500 leading-relaxed">
                Only unlock an executor after verifying proof of death (death
                certificate, legal documentation). This grants permanent read
                access to all ring assets and cannot be reversed.
              </p>
            </div>
          )}
        </section>
      )}
    </main>
  );
}
