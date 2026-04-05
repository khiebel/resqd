"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { API_URL, base64ToBytes, getCrypto } from "../lib/resqdCrypto";
import {
  fetchMe,
  loadMasterKey,
  loadX25519Identity,
  saveRingPrivkey,
  logout,
  type SessionUser,
} from "../lib/passkey";

interface RingSummary {
  ring_id: string;
  name: string;
  role: string;
  member_count: number;
  created_at: number;
}

interface MemberSummary {
  user_id: string;
  email: string;
  role: string;
  invited_at: number;
}

interface RingDetail {
  ring_id: string;
  name: string;
  ring_pubkey_x25519_b64: string;
  owner_user_id: string;
  created_at: number;
  members: MemberSummary[];
}

type ViewState =
  | { phase: "loading" }
  | { phase: "list"; rings: RingSummary[] }
  | { phase: "detail"; ring: RingDetail; myRole: string }
  | { phase: "error"; message: string };

function formatTimestamp(secs: number): string {
  if (!secs) return "—";
  return new Date(secs * 1000).toLocaleString();
}

export default function RingsPage() {
  const [user, setUser] = useState<SessionUser | null>(null);
  const [view, setView] = useState<ViewState>({ phase: "loading" });
  const [createName, setCreateName] = useState("");
  const [creating, setCreating] = useState(false);
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteRole, setInviteRole] = useState("adult");
  const [inviting, setInviting] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      const me = await fetchMe();
      if (!me || !loadMasterKey()) {
        window.location.href = "/login/";
        return;
      }
      setUser(me);
      await loadRings();
    })();
  }, []);

  const loadRings = useCallback(async () => {
    try {
      const resp = await fetch(`${API_URL}/rings`, { credentials: "include" });
      if (!resp.ok) throw new Error(`${resp.status}`);
      const rings: RingSummary[] = await resp.json();
      setView({ phase: "list", rings });
    } catch (e) {
      setView({
        phase: "error",
        message: e instanceof Error ? e.message : String(e),
      });
    }
  }, []);

  const onCreate = useCallback(async () => {
    setCreating(true);
    setActionError(null);
    try {
      const ident = loadX25519Identity();
      if (!ident) throw new Error("X25519 identity not loaded — re-login");
      const crypto = await getCrypto();

      // Generate ring keypair.
      const ringIdentJson = crypto.x25519_generate_identity();
      const ringIdent = JSON.parse(ringIdentJson) as {
        public_b64: string;
        private_b64: string;
      };

      // Client-generated ring_id (UUID). Needed before POST because
      // the ECDH-to-self wrap key derivation binds ring_id into HKDF.
      const ringId = crypto.hash_bytes(
        new TextEncoder().encode(Date.now() + Math.random().toString()),
      ).slice(0, 36);
      // Actually use a proper UUID shape:
      const uuid = [
        ringId.slice(0, 8),
        ringId.slice(8, 12),
        "4" + ringId.slice(13, 16),
        ((parseInt(ringId[16], 16) & 0x3) | 0x8).toString(16) + ringId.slice(17, 20),
        ringId.slice(20, 32),
      ].join("-");

      // Wrap ring privkey for self via ECDH-to-self.
      const wrapKeyB64 = crypto.x25519_sender_wrap_key(
        ident.privB64,
        ident.pubB64,
        uuid,
      );
      const wrapKey = base64ToBytes(wrapKeyB64);
      const ringPrivBytes = base64ToBytes(ringIdent.private_b64);
      const wrappedJson = crypto.encrypt_data(wrapKey, ringPrivBytes);
      const wrappedB64 = btoa(wrappedJson);

      const resp = await fetch(`${API_URL}/rings`, {
        method: "POST",
        credentials: "include",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          name: createName.trim(),
          ring_id: uuid,
          ring_pubkey_x25519_b64: ringIdent.public_b64,
          wrapped_ring_privkey_b64: wrappedB64,
        }),
      });
      if (!resp.ok) throw new Error(await resp.text());

      // Cache ring privkey in session so we can immediately upload to it.
      saveRingPrivkey(uuid, ringIdent.private_b64);

      setCreateName("");
      await loadRings();
    } catch (e) {
      setActionError(e instanceof Error ? e.message : String(e));
    } finally {
      setCreating(false);
    }
  }, [createName, loadRings]);

  const openDetail = useCallback(async (ringId: string) => {
    try {
      const resp = await fetch(
        `${API_URL}/rings/${encodeURIComponent(ringId)}`,
        { credentials: "include" },
      );
      if (!resp.ok) throw new Error(`${resp.status}`);
      const ring: RingDetail = await resp.json();

      // Find caller's role.
      const meResp = await fetch(
        `${API_URL}/rings/${encodeURIComponent(ringId)}/me`,
        { credentials: "include" },
      );
      const meData = meResp.ok
        ? ((await meResp.json()) as { role?: string })
        : {};

      setView({
        phase: "detail",
        ring,
        myRole: meData.role ?? "unknown",
      });
      setInviteEmail("");
      setInviteRole("adult");
      setActionError(null);
    } catch (e) {
      setActionError(e instanceof Error ? e.message : String(e));
    }
  }, []);

  const onInvite = useCallback(async () => {
    if (view.phase !== "detail") return;
    setInviting(true);
    setActionError(null);
    try {
      const ident = loadX25519Identity();
      if (!ident) throw new Error("X25519 identity not loaded");
      const crypto = await getCrypto();
      const ringId = view.ring.ring_id;

      // Look up invitee's pubkey.
      const lookupResp = await fetch(
        `${API_URL}/users/lookup?email=${encodeURIComponent(inviteEmail.trim())}`,
        { credentials: "include" },
      );
      if (!lookupResp.ok) {
        throw new Error(
          lookupResp.status === 404
            ? "user not found or has no identity yet"
            : `lookup failed: ${lookupResp.status}`,
        );
      }
      const recipient = (await lookupResp.json()) as {
        pubkey_x25519_b64: string;
      };

      // We need the ring privkey to re-wrap for the invitee.
      const { ensureRingPrivkey } = await import("../lib/passkey");
      const ringPrivB64 = await ensureRingPrivkey(ringId);
      if (!ringPrivB64) throw new Error("could not unwrap ring privkey");

      // Wrap ring privkey for the invitee via ECDH.
      const wrapKeyB64 = crypto.x25519_sender_wrap_key(
        ident.privB64,
        recipient.pubkey_x25519_b64,
        ringId,
      );
      const wrapKey = base64ToBytes(wrapKeyB64);
      const ringPrivBytes = base64ToBytes(ringPrivB64);
      const wrappedJson = crypto.encrypt_data(wrapKey, ringPrivBytes);
      const wrappedB64 = btoa(wrappedJson);

      const resp = await fetch(
        `${API_URL}/rings/${encodeURIComponent(ringId)}/members`,
        {
          method: "POST",
          credentials: "include",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            invitee_email: inviteEmail.trim(),
            role: inviteRole,
            wrapped_ring_privkey_b64: wrappedB64,
            inviter_pubkey_x25519_b64: ident.pubB64,
          }),
        },
      );
      if (!resp.ok) throw new Error(await resp.text());

      setInviteEmail("");
      await openDetail(ringId);
    } catch (e) {
      setActionError(e instanceof Error ? e.message : String(e));
    } finally {
      setInviting(false);
    }
  }, [view, inviteEmail, inviteRole, openDetail]);

  const onRemoveMember = useCallback(
    async (email: string) => {
      if (view.phase !== "detail") return;
      if (!confirm(`Remove ${email} from this ring?`)) return;
      try {
        const resp = await fetch(
          `${API_URL}/rings/${encodeURIComponent(view.ring.ring_id)}/members/${encodeURIComponent(email)}`,
          { method: "DELETE", credentials: "include" },
        );
        if (!resp.ok) throw new Error(await resp.text());
        await openDetail(view.ring.ring_id);
      } catch (e) {
        setActionError(e instanceof Error ? e.message : String(e));
      }
    },
    [view, openDetail],
  );

  return (
    <main className="mx-auto max-w-3xl px-6 py-12 text-slate-100">
      <header className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-3xl font-bold">Family Rings</h1>
          {user && (
            <p className="text-xs text-slate-500 mt-1">
              Signed in as <span className="text-slate-300">{user.email}</span>
            </p>
          )}
        </div>
        <div className="flex items-center gap-4">
          <Link
            href="/vault/"
            className="text-xs text-amber-400 hover:underline"
          >
            My vault
          </Link>
          <Link
            href="/settings/"
            className="text-xs text-slate-400 hover:text-slate-200"
          >
            Settings
          </Link>
          <button
            onClick={async () => {
              await logout();
              window.location.href = "/login/";
            }}
            className="text-xs text-slate-400 hover:text-slate-200"
          >
            Sign out
          </button>
        </div>
      </header>

      {actionError && (
        <div className="mb-6 bg-red-950/40 border border-red-900 rounded-lg p-3 text-sm text-red-300">
          {actionError}
        </div>
      )}

      {view.phase === "loading" && (
        <p className="text-slate-500 text-sm">Loading…</p>
      )}
      {view.phase === "error" && (
        <p className="text-red-400 text-sm">Error: {view.message}</p>
      )}

      {/* ──── Ring list ──── */}
      {view.phase === "list" && (
        <>
          <section className="mb-8 bg-slate-900 border border-slate-800 rounded-lg p-4">
            <h2 className="text-sm font-semibold text-slate-400 uppercase tracking-wide mb-3">
              Create a new ring
            </h2>
            <div className="flex gap-2">
              <input
                type="text"
                value={createName}
                onChange={(e) => setCreateName(e.target.value)}
                placeholder="Ring name (e.g. Hiebel Family)"
                disabled={creating}
                className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm"
              />
              <button
                onClick={onCreate}
                disabled={creating || !createName.trim()}
                className="rounded-lg bg-violet-500 text-slate-50 font-semibold px-4 py-2 text-sm disabled:opacity-30"
              >
                {creating ? "Creating…" : "Create"}
              </button>
            </div>
          </section>

          {view.rings.length === 0 ? (
            <section className="border-2 border-dashed border-slate-800 rounded-xl p-12 text-center">
              <p className="text-slate-400 mb-2">
                You&apos;re not a member of any rings yet.
              </p>
              <p className="text-xs text-slate-500">
                A ring is a shared vault group for your family. Create one
                above, then invite family members. Everyone in the ring can
                read ring-owned files — Owner and Adult roles can also
                upload and delete.
              </p>
            </section>
          ) : (
            <section className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
              <table className="w-full text-sm">
                <thead className="bg-slate-950 text-slate-400 text-xs uppercase">
                  <tr>
                    <th className="text-left py-2 px-4 font-medium">Ring</th>
                    <th className="text-left py-2 px-4 font-medium">Role</th>
                    <th className="text-left py-2 px-4 font-medium">Members</th>
                    <th className="text-right py-2 px-4 font-medium"></th>
                  </tr>
                </thead>
                <tbody>
                  {view.rings.map((r) => (
                    <tr
                      key={r.ring_id}
                      className="border-t border-slate-800 hover:bg-slate-800/40"
                    >
                      <td className="py-3 px-4">
                        <div className="text-slate-100">{r.name}</div>
                        <div className="text-xs text-slate-500 font-mono">
                          {r.ring_id.slice(0, 8)}…
                        </div>
                      </td>
                      <td className="py-3 px-4 text-xs">
                        <span className="bg-violet-500/20 text-violet-300 px-1.5 py-0.5 rounded uppercase tracking-wider text-[10px]">
                          {r.role}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-xs text-slate-400">
                        {r.member_count}
                      </td>
                      <td className="py-3 px-4 text-right">
                        <button
                          onClick={() => openDetail(r.ring_id)}
                          className="text-amber-400 hover:underline text-xs"
                        >
                          Manage →
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </section>
          )}
        </>
      )}

      {/* ──── Ring detail ──── */}
      {view.phase === "detail" && (
        <>
          <button
            onClick={loadRings}
            className="text-xs text-amber-400 hover:underline mb-4 block"
          >
            ← Back to rings
          </button>

          <section className="bg-slate-900 border border-slate-800 rounded-xl p-5 mb-6">
            <h2 className="text-xl font-bold mb-1">{view.ring.name}</h2>
            <p className="text-xs text-slate-500 mb-1">
              Ring ID:{" "}
              <span className="font-mono">{view.ring.ring_id}</span>
            </p>
            <p className="text-xs text-slate-500">
              Created {formatTimestamp(view.ring.created_at)} · Your role:{" "}
              <span className="text-violet-300 uppercase">{view.myRole}</span>
            </p>
          </section>

          {/* Invite form */}
          {(view.myRole === "owner" || view.myRole === "adult") && (
            <section className="mb-6 bg-slate-900 border border-slate-800 rounded-lg p-4">
              <h3 className="text-sm font-semibold text-slate-400 uppercase tracking-wide mb-3">
                Invite a member
              </h3>
              <div className="flex gap-2 items-end">
                <div className="flex-1">
                  <label className="block text-xs text-slate-500 mb-1">
                    Email
                  </label>
                  <input
                    type="email"
                    value={inviteEmail}
                    onChange={(e) => setInviteEmail(e.target.value)}
                    placeholder="person@example.com"
                    disabled={inviting}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm"
                  />
                </div>
                <div>
                  <label className="block text-xs text-slate-500 mb-1">
                    Role
                  </label>
                  <select
                    value={inviteRole}
                    onChange={(e) => setInviteRole(e.target.value)}
                    disabled={inviting}
                    className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm"
                  >
                    {view.myRole === "owner" && (
                      <option value="owner">Owner</option>
                    )}
                    <option value="adult">Adult</option>
                    <option value="child">Child</option>
                    <option value="executor">Executor</option>
                  </select>
                </div>
                <button
                  onClick={onInvite}
                  disabled={inviting || !inviteEmail.trim()}
                  className="rounded-lg bg-violet-500 text-slate-50 font-semibold px-4 py-2 text-sm disabled:opacity-30"
                >
                  {inviting ? "Inviting…" : "Invite"}
                </button>
              </div>
              <p className="text-xs text-slate-500 mt-2">
                Members can view all ring assets. Owner &amp; Adult can
                also upload and delete. Child is read-only. Executor
                unlocks only after an estate trigger (coming soon).
              </p>
            </section>
          )}

          {/* Member list */}
          <section className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
            <table className="w-full text-sm">
              <thead className="bg-slate-950 text-slate-400 text-xs uppercase">
                <tr>
                  <th className="text-left py-2 px-4 font-medium">
                    Member
                  </th>
                  <th className="text-left py-2 px-4 font-medium">Role</th>
                  <th className="text-left py-2 px-4 font-medium">
                    Joined
                  </th>
                  <th className="text-right py-2 px-4 font-medium"></th>
                </tr>
              </thead>
              <tbody>
                {view.ring.members.map((m) => (
                  <tr
                    key={m.user_id}
                    className="border-t border-slate-800"
                  >
                    <td className="py-3 px-4 text-slate-300 font-mono text-xs">
                      {m.email}
                    </td>
                    <td className="py-3 px-4">
                      <span className="bg-violet-500/20 text-violet-300 px-1.5 py-0.5 rounded uppercase tracking-wider text-[10px]">
                        {m.role}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-xs text-slate-400">
                      {formatTimestamp(m.invited_at)}
                    </td>
                    <td className="py-3 px-4 text-right">
                      {view.myRole === "owner" &&
                        m.user_id !== view.ring.owner_user_id && (
                          <button
                            onClick={() => onRemoveMember(m.email)}
                            className="text-xs text-slate-500 hover:text-red-400"
                          >
                            Remove
                          </button>
                        )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>
        </>
      )}
    </main>
  );
}
