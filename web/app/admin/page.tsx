"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";

// Admin XHRs go through the friendly hostname, NOT the raw API GW. The
// path-scoped CF Access app at api.resqd.ai/admin injects the user-email
// header that require_admin() requires, and the resqd-api-proxy Worker
// adds the origin secret. The user-facing API_URL points directly at API
// Gateway and bypasses both — that path is exempted from origin_secret
// for /auth, /vault, /users, /rings only. /admin is intentionally not.
const ADMIN_API_URL = "https://api.resqd.ai";

// ── Types ───────────────────────────────────────────────────────────

interface AdminUser {
  email: string;
  user_id: string;
  display_name: string;
  created_at: number;
  storage_used_bytes: number;
  has_x25519_identity: boolean;
  disabled?: boolean;
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

interface AuditEntry {
  timestamp: number;
  admin_email: string;
  action: string;
  target: string;
  detail: string;
}

interface SecuritySummary {
  user_security: {
    total_users: number;
    users_with_identity: number;
    users_without_identity: number;
    disabled_users: number;
    recent_registrations: number;
  };
  generated_at: number;
}

interface MetricPoint {
  timestamp: number;
  value: number;
}

interface InfraMetrics {
  lambda: {
    invocations: MetricPoint[];
    errors: MetricPoint[];
    duration: MetricPoint[];
  };
  dynamo: Record<string, { item_count: number; size_bytes: number }>;
  s3: { object_count: number; total_size_bytes: number };
  generated_at: number;
}

interface EstateSummary {
  active_triggers: Array<{
    ring_id: string;
    ring_name: string;
    trigger_type: string;
    owner_user_id: string;
    last_owner_activity_at?: number;
    member_count: number;
  }>;
  completed_unlocks: Array<{
    ring_id: string;
    ring_name: string;
    executor_email: string;
    unlocked_at: number;
  }>;
  count: number;
}

type Tab = "dashboard" | "users" | "rings" | "estate" | "security" | "infra" | "audit";

const TAB_LABELS: Record<Tab, string> = {
  dashboard: "Dashboard",
  users: "Users",
  rings: "Rings",
  estate: "Estate",
  security: "Security",
  infra: "Infrastructure",
  audit: "Audit Log",
};

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

function formatTimestamp(secs: number): string {
  if (!secs) return "\u2014";
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
  const [tab, setTab] = useState<Tab>("dashboard");
  const [stats, setStats] = useState<AdminStats | null>(null);
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [rings, setRings] = useState<AdminRing[]>([]);
  const [selectedRing, setSelectedRing] = useState<AdminRingDetail | null>(null);
  const [unlocking, setUnlocking] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // New state for expanded tabs
  const [auditEntries, setAuditEntries] = useState<AuditEntry[]>([]);
  const [recentAudit, setRecentAudit] = useState<AuditEntry[]>([]);
  const [security, setSecurity] = useState<SecuritySummary | null>(null);
  const [infra, setInfra] = useState<InfraMetrics | null>(null);
  const [estate, setEstate] = useState<EstateSummary | null>(null);
  const [userSearch, setUserSearch] = useState("");
  const [auditFilter, setAuditFilter] = useState("all");
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  // Dedicated count of absorption failures surfaced on the dashboard
  // tile without waiting for the Audit tab's lazy-loaded full entries.
  const [absorptionFailureCount, setAbsorptionFailureCount] = useState<
    number | null
  >(null);
  // Track 2 Chunk 2.6 — absorption reaper state
  const [reaperRunning, setReaperRunning] = useState(false);
  const [reaperResult, setReaperResult] = useState<{
    window_minutes: number;
    considered: number;
    checked: number;
    passed: number;
    failed: { asset_id: string; reason: string; failed_shard_indices: number[] }[];
    skipped_reasons: Record<string, number>;
  } | null>(null);

  const fetchAdmin = useCallback(async (path: string) => {
    let resp: Response;
    try {
      resp = await fetch(`${ADMIN_API_URL}${path}`, {
        credentials: "include",
      });
    } catch {
      // TypeError from CORS failure — CF Access on api.resqd.ai/admin
      // tried to redirect to cloudflareaccess.com which doesn't have
      // the right CORS headers.  Bounce through the Worker to establish
      // the CF_Authorization cookie via SSO, then come back.
      const bounceUrl = `${ADMIN_API_URL}/admin/bounce?return_url=${encodeURIComponent(window.location.href)}`;
      window.location.href = bounceUrl;
      // Hang so no further fetches fire while navigating away.
      return new Promise(() => {});
    }
    if (resp.status === 403) {
      throw new Error("admin access denied \u2014 your email is not in the admin list");
    }
    if (resp.status === 401) {
      throw new Error("unauthorized \u2014 admin endpoints require CF Access authentication");
    }
    if (!resp.ok) {
      throw new Error(`${resp.status} ${await resp.text()}`);
    }
    return resp.json();
  }, []);

  const postAdmin = useCallback(async (path: string) => {
    const resp = await fetch(`${ADMIN_API_URL}${path}`, {
      method: "POST",
      credentials: "include",
    });
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
  }, []);

  // Initial data load
  useEffect(() => {
    (async () => {
      try {
        const [s, u, r, audit, sec, absorption] = await Promise.all([
          fetchAdmin("/admin/stats"),
          fetchAdmin("/admin/users"),
          fetchAdmin("/admin/rings"),
          fetchAdmin("/admin/audit?limit=10").catch(() => ({ entries: [] })),
          fetchAdmin("/admin/security").catch(() => null),
          fetchAdmin(
            "/admin/audit?limit=100&action=shard_absorption_failed",
          ).catch(() => ({ entries: [] })),
        ]);
        setStats(s);
        setUsers(u.users);
        setRings(r.rings);
        setRecentAudit(audit.entries || []);
        if (sec) setSecurity(sec);
        setAbsorptionFailureCount((absorption.entries || []).length);
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      } finally {
        setLoading(false);
      }
    })();
  }, [fetchAdmin]);

  // Lazy-load tab data
  useEffect(() => {
    if (tab === "audit" && auditEntries.length === 0) {
      fetchAdmin("/admin/audit?limit=100")
        .then((data) => setAuditEntries(data.entries || []))
        .catch(() => {});
    }
    if (tab === "security" && !security) {
      fetchAdmin("/admin/security")
        .then((data) => setSecurity(data))
        .catch(() => {});
    }
    if (tab === "infra" && !infra) {
      fetchAdmin("/admin/metrics")
        .then((data) => setInfra(data))
        .catch(() => {});
    }
    if (tab === "estate" && !estate) {
      fetchAdmin("/admin/estate")
        .then((data) => setEstate(data))
        .catch(() => {});
    }
  }, [tab, fetchAdmin, auditEntries.length, security, infra, estate]);

  const refetchUsers = useCallback(async () => {
    try {
      const u = await fetchAdmin("/admin/users");
      setUsers(u.users);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, [fetchAdmin]);

  const toggleUserDisabled = useCallback(async (email: string, currentlyDisabled: boolean) => {
    const action = currentlyDisabled ? "enable" : "disable";
    if (!confirm(`${currentlyDisabled ? "Enable" : "Disable"} user ${email}?`)) return;
    setActionLoading(email);
    try {
      await postAdmin(`/admin/users/${encodeURIComponent(email)}/${action}`);
      await refetchUsers();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setActionLoading(null);
    }
  }, [postAdmin, refetchUsers]);

  const resetQuota = useCallback(async (email: string) => {
    if (!confirm(`Reset storage quota for ${email}?`)) return;
    setActionLoading(email);
    try {
      await postAdmin(`/admin/users/${encodeURIComponent(email)}/reset-quota`);
      await refetchUsers();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setActionLoading(null);
    }
  }, [postAdmin, refetchUsers]);

  const viewRingMembers = useCallback(async (ringId: string) => {
    try {
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
        `${ADMIN_API_URL}/admin/rings/${encodeURIComponent(ringId)}/unlock-executor/${encodeURIComponent(executorEmail)}`,
        { method: "POST", credentials: "include" },
      );
      if (!resp.ok) throw new Error(await resp.text());
      const result = await resp.json();
      setError(null);
      alert(result.message || "Executor unlocked");
      await viewRingMembers(ringId);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setUnlocking(false);
    }
  }, [viewRingMembers]);

  // Filtered users
  const filteredUsers = userSearch
    ? users.filter((u) => u.email.toLowerCase().includes(userSearch.toLowerCase()))
    : users;

  // Filtered audit
  const filteredAudit = auditFilter === "all"
    ? auditEntries
    : auditEntries.filter((e) => e.action === auditFilter);

  // Audit row color
  const auditRowClass = (action: string) => {
    if (action === "shard_absorption_failed") return "bg-red-500/10";
    if (action.includes("disable") || action.includes("unlock")) return "bg-red-500/5";
    if (action.includes("reset-quota")) return "bg-amber-500/5";
    return "";
  };

  // Unique audit actions for filter dropdown
  const auditActions = Array.from(new Set(auditEntries.map((e) => e.action)));

  // Track 2 visibility — count absorption failures in the recent window.
  // Prefer the dedicated-fetch number; fall back to whatever's already
  // loaded in the full audit entries slice if the dedicated fetch
  // hasn't resolved yet.
  const absorptionFailures24h =
    absorptionFailureCount ??
    auditEntries.filter((e) => e.action === "shard_absorption_failed").length;

  if (loading) {
    return (
      <main className="mx-auto max-w-5xl px-6 py-16 text-slate-100">
        <p className="text-slate-400">Loading admin console\u2026</p>
      </main>
    );
  }

  if (error) {
    return (
      <main className="mx-auto max-w-5xl px-6 py-16 text-slate-100">
        <h1 className="text-3xl font-bold mb-4">Admin Console</h1>
        <p className="text-red-400 mb-4">{error}</p>
        <button
          onClick={() => setError(null)}
          className="text-xs text-amber-400 hover:underline mr-4"
        >
          Dismiss
        </button>
        <Link href="/vault/" className="text-slate-400 text-sm hover:underline">
          \u2190 Back to vault
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
          \u2190 Back to vault
        </Link>
      </header>

      {/* Tab bar */}
      <div className="flex gap-1 mb-8 bg-slate-900 border border-slate-800 rounded-lg p-1 w-fit overflow-x-auto">
        {(Object.keys(TAB_LABELS) as Tab[]).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-4 py-1.5 rounded text-sm font-medium transition-colors whitespace-nowrap ${
              tab === t
                ? "bg-violet-500 text-white"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            {TAB_LABELS[t]}
          </button>
        ))}
      </div>

      {/* ──── Dashboard tab ──── */}
      {tab === "dashboard" && stats && (
        <div>
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
            <StatCard
              label="Disabled users"
              value={security?.user_security?.disabled_users ?? "\u2014"}
            />
            <StatCard
              label="Recent registrations"
              value={security?.user_security?.recent_registrations ?? "\u2014"}
              sub="last 7 days"
            />
            <StatCard
              label="Audit actions"
              value={recentAudit.length}
              sub="last 10 entries loaded"
            />
            <StatCard
              label="Failed absorptions"
              value={absorptionFailures24h}
              sub={
                absorptionFailures24h > 0
                  ? "investigate in audit log"
                  : "steady state"
              }
            />
          </div>

          {/* Recent Activity */}
          {recentAudit.length > 0 && (
            <div className="mt-8">
              <h2 className="text-lg font-semibold mb-3">Recent Activity</h2>
              <section className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
                <table className="w-full text-sm">
                  <thead className="bg-slate-950 text-slate-400 text-xs uppercase">
                    <tr>
                      <th className="text-left py-2 px-4 font-medium">Timestamp</th>
                      <th className="text-left py-2 px-4 font-medium">Admin</th>
                      <th className="text-left py-2 px-4 font-medium">Action</th>
                      <th className="text-left py-2 px-4 font-medium">Target</th>
                    </tr>
                  </thead>
                  <tbody>
                    {recentAudit.map((entry, i) => (
                      <tr
                        key={`${entry.timestamp}-${i}`}
                        className="border-t border-slate-800 hover:bg-slate-800/40"
                      >
                        <td className="py-2 px-4 text-xs text-slate-400">
                          {formatTimestamp(entry.timestamp)}
                        </td>
                        <td className="py-2 px-4 text-xs text-slate-300">
                          {entry.admin_email}
                        </td>
                        <td className="py-2 px-4">
                          <span className="text-[10px] uppercase tracking-wider bg-violet-500/20 text-violet-300 px-1.5 py-0.5 rounded">
                            {entry.action}
                          </span>
                        </td>
                        <td className="py-2 px-4 text-xs text-slate-300 font-mono">
                          {entry.target}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </section>
            </div>
          )}
        </div>
      )}

      {/* ──── Users tab ──── */}
      {tab === "users" && (
        <section>
          <div className="mb-4">
            <input
              type="text"
              placeholder="Search by email\u2026"
              value={userSearch}
              onChange={(e) => setUserSearch(e.target.value)}
              className="bg-slate-900 border border-slate-800 rounded-lg px-4 py-2 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-violet-500 w-full max-w-sm"
            />
          </div>
          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
            <table className="w-full text-sm">
              <thead className="bg-slate-950 text-slate-400 text-xs uppercase">
                <tr>
                  <th className="text-left py-2 px-4 font-medium">Email</th>
                  <th className="text-left py-2 px-4 font-medium">Status</th>
                  <th className="text-left py-2 px-4 font-medium">Storage</th>
                  <th className="text-left py-2 px-4 font-medium">Identity</th>
                  <th className="text-left py-2 px-4 font-medium">Joined</th>
                  <th className="text-right py-2 px-4 font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredUsers.map((u) => (
                  <tr
                    key={u.user_id}
                    className="border-t border-slate-800 hover:bg-slate-800/40"
                  >
                    <td className="py-3 px-4">
                      <div className="text-slate-100">{u.email}</div>
                      <div className="text-xs text-slate-500 font-mono">
                        {u.user_id.slice(0, 12)}\u2026
                      </div>
                    </td>
                    <td className="py-3 px-4">
                      {u.disabled ? (
                        <span className="text-[10px] uppercase tracking-wider bg-red-500/20 text-red-300 px-1.5 py-0.5 rounded">
                          Disabled
                        </span>
                      ) : (
                        <span className="text-[10px] uppercase tracking-wider bg-green-500/20 text-green-300 px-1.5 py-0.5 rounded">
                          Active
                        </span>
                      )}
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
                    <td className="py-3 px-4 text-right space-x-2">
                      <button
                        onClick={() => toggleUserDisabled(u.email, !!u.disabled)}
                        disabled={actionLoading === u.email}
                        className={`text-xs font-medium px-2 py-1 rounded ${
                          u.disabled
                            ? "bg-green-600/20 text-green-300 hover:bg-green-600/30"
                            : "bg-red-600/20 text-red-300 hover:bg-red-600/30"
                        } disabled:opacity-30`}
                      >
                        {actionLoading === u.email ? "\u2026" : u.disabled ? "Enable" : "Disable"}
                      </button>
                      <button
                        onClick={() => resetQuota(u.email)}
                        disabled={actionLoading === u.email}
                        className="text-xs font-medium px-2 py-1 rounded bg-amber-600/20 text-amber-300 hover:bg-amber-600/30 disabled:opacity-30"
                      >
                        Reset Quota
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
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
                    Executor unlocked
                  </th>
                  <th className="text-left py-2 px-4 font-medium">
                    Last owner activity
                  </th>
                  <th className="text-left py-2 px-4 font-medium">Created</th>
                </tr>
              </thead>
              <tbody>
                {rings.map((r) => {
                  const hasUnlock = estate?.completed_unlocks?.some(
                    (u) => u.ring_id === r.ring_id
                  );
                  return (
                    <tr
                      key={r.ring_id}
                      className="border-t border-slate-800 hover:bg-slate-800/40"
                    >
                      <td className="py-3 px-4">
                        <div className="text-slate-100">{r.name}</div>
                        <div className="text-xs text-slate-500 font-mono">
                          {r.ring_id.slice(0, 12)}\u2026
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
                          <span className="text-xs text-slate-500">\u2014</span>
                        )}
                      </td>
                      <td className="py-3 px-4">
                        {hasUnlock ? (
                          <span className="text-[10px] uppercase tracking-wider bg-red-500/20 text-red-300 px-1.5 py-0.5 rounded">
                            Yes
                          </span>
                        ) : (
                          <span className="text-xs text-slate-500">\u2014</span>
                        )}
                      </td>
                      <td className="py-3 px-4 text-xs text-slate-400">
                        {r.last_owner_activity_at
                          ? timeAgo(r.last_owner_activity_at)
                          : "\u2014"}
                      </td>
                      <td className="py-3 px-4 text-xs text-slate-400">
                        {formatTimestamp(r.created_at)}
                      </td>
                      <td className="py-3 px-4 text-right">
                        <button
                          onClick={() => viewRingMembers(r.ring_id)}
                          className="text-xs text-amber-400 hover:underline"
                        >
                          Members \u2192
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}

          {/* Ring member detail + executor unlock */}
          {selectedRing && (
            <div className="mt-6 bg-slate-950 border border-slate-800 rounded-xl p-5">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold">{selectedRing.name} \u2014 Members</h3>
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
                            {unlocking ? "Unlocking\u2026" : "Unlock (proof of death)"}
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

      {/* ──── Estate tab ──── */}
      {tab === "estate" && (
        <div>
          {!estate ? (
            <p className="text-slate-400 text-sm">Loading estate data\u2026</p>
          ) : (
            <>
              {/* Active Triggers */}
              <h2 className="text-lg font-semibold mb-3">Active Triggers</h2>
              {estate.active_triggers.length === 0 ? (
                <p className="text-sm text-slate-400 mb-8">No active triggers.</p>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-8">
                  {estate.active_triggers.map((t) => (
                    <div
                      key={t.ring_id}
                      className="bg-slate-900 border border-slate-800 rounded-lg p-4"
                    >
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-sm font-semibold text-slate-100">
                          {t.ring_name}
                        </span>
                        <span
                          className={`text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded ${
                            t.trigger_type === "inactivity"
                              ? "bg-amber-500/20 text-amber-300"
                              : "bg-violet-500/20 text-violet-300"
                          }`}
                        >
                          {t.trigger_type}
                        </span>
                      </div>
                      <div className="text-xs text-slate-400 space-y-1">
                        <div>Owner: <span className="text-slate-300 font-mono">{t.owner_user_id.slice(0, 12)}\u2026</span></div>
                        <div>Last activity: {t.last_owner_activity_at ? timeAgo(t.last_owner_activity_at) : "\u2014"}</div>
                        <div>Members: {t.member_count}</div>
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {/* Completed Unlocks */}
              <h2 className="text-lg font-semibold mb-3">Completed Unlocks</h2>
              {estate.completed_unlocks.length === 0 ? (
                <p className="text-sm text-slate-400">No completed unlocks.</p>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {estate.completed_unlocks.map((u, i) => (
                    <div
                      key={`${u.ring_id}-${i}`}
                      className="bg-slate-900 border border-slate-800 rounded-lg p-4"
                    >
                      <div className="text-sm font-semibold text-slate-100 mb-2">
                        {u.ring_name}
                      </div>
                      <div className="text-xs text-slate-400 space-y-1">
                        <div>Executor: <span className="text-slate-300 font-mono">{u.executor_email}</span></div>
                        <div>Unlocked: {formatTimestamp(u.unlocked_at)}</div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </>
          )}
        </div>
      )}

      {/* ──── Security tab ──── */}
      {tab === "security" && (
        <div>
          {!security ? (
            <p className="text-slate-400 text-sm">Loading security data\u2026</p>
          ) : (
            <>
              <div className="grid grid-cols-2 md:grid-cols-3 gap-4 mb-8">
                <StatCard
                  label="Total users"
                  value={security.user_security.total_users}
                />
                <StatCard
                  label="With identity"
                  value={security.user_security.users_with_identity}
                />
                <StatCard
                  label="Without identity"
                  value={security.user_security.users_without_identity}
                />
                <StatCard
                  label="Disabled"
                  value={security.user_security.disabled_users}
                />
                <StatCard
                  label="Recent registrations"
                  value={security.user_security.recent_registrations}
                  sub="last 7 days"
                />
              </div>

              {/* Coming soon placeholders */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
                {["Failed Auth Attempts", "Rate Limit Violations", "Geo-Block Events"].map((section) => (
                  <div
                    key={section}
                    className="bg-slate-900 border border-slate-800 rounded-lg p-4"
                  >
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-xs text-slate-500 uppercase tracking-wider">
                        {section}
                      </span>
                      <span className="text-[10px] uppercase tracking-wider bg-amber-500/20 text-amber-300 px-1.5 py-0.5 rounded">
                        Coming Soon
                      </span>
                    </div>
                    <div className="text-2xl font-bold text-slate-600">\u2014</div>
                  </div>
                ))}
              </div>

              {/* Absorption reaper — Track 2 Chunk 2.6 */}
              <div className="bg-slate-900 border border-slate-800 rounded-lg p-5">
                <div className="flex items-center justify-between mb-3">
                  <div>
                    <h3 className="text-sm font-semibold">
                      Absorption Reaper
                    </h3>
                    <p className="text-xs text-slate-500 mt-1 max-w-xl">
                      Walks streaming vaults committed in the window and
                      re-runs the full-shard BLAKE3 absorption check.
                      Catches first-hour bit-rot. Failures are logged to
                      the audit stream as `shard_absorption_failed`.
                    </p>
                  </div>
                  <button
                    type="button"
                    disabled={reaperRunning}
                    onClick={async () => {
                      setReaperRunning(true);
                      setReaperResult(null);
                      try {
                        const res = await postAdmin("/admin/reaper/scan");
                        setReaperResult(res);
                      } catch (e) {
                        setError(e instanceof Error ? e.message : String(e));
                      } finally {
                        setReaperRunning(false);
                      }
                    }}
                    className={`px-4 py-2 rounded text-sm font-medium ${
                      reaperRunning
                        ? "bg-slate-800 text-slate-500"
                        : "bg-amber-500 text-slate-900 hover:bg-amber-400"
                    }`}
                  >
                    {reaperRunning ? "Scanning\u2026" : "Run scan"}
                  </button>
                </div>
                {reaperResult && (
                  <div className="mt-4 text-sm">
                    <div className="grid grid-cols-4 gap-3 mb-3">
                      <StatCard
                        label="Considered"
                        value={reaperResult.considered}
                      />
                      <StatCard
                        label="Checked"
                        value={reaperResult.checked}
                      />
                      <StatCard
                        label="Passed"
                        value={reaperResult.passed}
                      />
                      <StatCard
                        label="Failed"
                        value={reaperResult.failed.length}
                        sub={
                          reaperResult.failed.length > 0
                            ? "investigate"
                            : "steady state"
                        }
                      />
                    </div>
                    {reaperResult.failed.length > 0 ? (
                      <div className="bg-red-950/30 border border-red-800 rounded p-3">
                        <h4 className="text-xs uppercase tracking-wider text-red-300 mb-2">
                          Failed absorptions
                        </h4>
                        <ul className="space-y-1 font-mono text-xs">
                          {reaperResult.failed.map((f) => (
                            <li key={f.asset_id}>
                              <span className="text-red-300">
                                {f.asset_id}
                              </span>{" "}
                              — {f.reason} · shards{" "}
                              {f.failed_shard_indices.join(", ")}
                            </li>
                          ))}
                        </ul>
                      </div>
                    ) : (
                      <p className="text-green-400 text-xs">
                        \u2713 All checked vaults passed absorption.
                      </p>
                    )}
                    {Object.keys(reaperResult.skipped_reasons).length > 0 && (
                      <p className="text-xs text-slate-500 mt-2">
                        Skipped:{" "}
                        {Object.entries(reaperResult.skipped_reasons)
                          .map(([k, v]) => `${k}=${v}`)
                          .join(", ")}
                      </p>
                    )}
                  </div>
                )}
              </div>
            </>
          )}
        </div>
      )}

      {/* ──── Infrastructure tab ──── */}
      {tab === "infra" && (
        <div>
          {!infra ? (
            <p className="text-slate-400 text-sm">Loading infrastructure metrics\u2026</p>
          ) : (
            <>
              {/* Lambda Metrics */}
              <h2 className="text-lg font-semibold mb-3">Lambda Metrics (24h)</h2>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
                <StatCard
                  label="Total invocations"
                  value={infra.lambda.invocations.reduce((a, b) => a + b.value, 0)}
                  sub={`Hourly: ${infra.lambda.invocations.map((p) => p.value).join(", ")}`}
                />
                <StatCard
                  label="Total errors"
                  value={infra.lambda.errors.reduce((a, b) => a + b.value, 0)}
                  sub={`Hourly: ${infra.lambda.errors.map((p) => p.value).join(", ")}`}
                />
                <StatCard
                  label="Avg duration"
                  value={
                    infra.lambda.duration.length > 0
                      ? `${Math.round(infra.lambda.duration.reduce((a, b) => a + b.value, 0) / infra.lambda.duration.length)}ms`
                      : "\u2014"
                  }
                  sub={`Hourly: ${infra.lambda.duration.map((p) => `${Math.round(p.value)}ms`).join(", ")}`}
                />
              </div>

              {/* DynamoDB Tables */}
              <h2 className="text-lg font-semibold mb-3">DynamoDB Tables</h2>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-8">
                {Object.entries(infra.dynamo).map(([table, info]) => (
                  <StatCard
                    key={table}
                    label={table}
                    value={`${info.item_count.toLocaleString()} items`}
                    sub={formatBytes(info.size_bytes)}
                  />
                ))}
              </div>

              {/* S3 Storage */}
              <h2 className="text-lg font-semibold mb-3">S3 Storage</h2>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <StatCard
                  label="Objects"
                  value={infra.s3.object_count.toLocaleString()}
                />
                <StatCard
                  label="Total size"
                  value={formatBytes(infra.s3.total_size_bytes)}
                />
              </div>
            </>
          )}
        </div>
      )}

      {/* ──── Audit Log tab ──── */}
      {tab === "audit" && (
        <section>
          <div className="mb-4">
            <select
              value={auditFilter}
              onChange={(e) => setAuditFilter(e.target.value)}
              className="bg-slate-900 border border-slate-800 rounded-lg px-4 py-2 text-sm text-slate-100 focus:outline-none focus:border-violet-500"
            >
              <option value="all">All actions</option>
              {auditActions.map((a) => (
                <option key={a} value={a}>
                  {a}
                </option>
              ))}
            </select>
          </div>
          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
            {filteredAudit.length === 0 ? (
              <div className="p-6 text-sm text-slate-400">No audit entries.</div>
            ) : (
              <table className="w-full text-sm">
                <thead className="bg-slate-950 text-slate-400 text-xs uppercase">
                  <tr>
                    <th className="text-left py-2 px-4 font-medium">Timestamp</th>
                    <th className="text-left py-2 px-4 font-medium">Admin</th>
                    <th className="text-left py-2 px-4 font-medium">Action</th>
                    <th className="text-left py-2 px-4 font-medium">Target</th>
                    <th className="text-left py-2 px-4 font-medium">Detail</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredAudit.map((entry, i) => (
                    <tr
                      key={`${entry.timestamp}-${i}`}
                      className={`border-t border-slate-800 hover:bg-slate-800/40 ${auditRowClass(entry.action)}`}
                    >
                      <td className="py-2 px-4 text-xs text-slate-400">
                        {formatTimestamp(entry.timestamp)}
                      </td>
                      <td className="py-2 px-4 text-xs text-slate-300">
                        {entry.admin_email}
                      </td>
                      <td className="py-2 px-4">
                        <span className="text-[10px] uppercase tracking-wider bg-violet-500/20 text-violet-300 px-1.5 py-0.5 rounded">
                          {entry.action}
                        </span>
                      </td>
                      <td className="py-2 px-4 text-xs text-slate-300 font-mono">
                        {entry.target}
                      </td>
                      <td className="py-2 px-4 text-xs text-slate-400">
                        {entry.detail || "\u2014"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </section>
      )}
    </main>
  );
}
