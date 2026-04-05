"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  registerWithPasskey,
  isPasskeySupported,
  fetchMe,
} from "../lib/passkey";

type State =
  | { phase: "idle" }
  | { phase: "checking" }
  | { phase: "working" }
  | { phase: "done"; email: string }
  | { phase: "error"; message: string };

export default function SignupPage() {
  const [email, setEmail] = useState("");
  const [state, setState] = useState<State>({ phase: "checking" });

  useEffect(() => {
    (async () => {
      if (!isPasskeySupported()) {
        setState({
          phase: "error",
          message:
            "passkeys are not supported in this browser — try Chrome, Safari, or Edge with Touch ID / Windows Hello",
        });
        return;
      }
      const me = await fetchMe();
      if (me) {
        // Already signed in — bounce to vault. Use location so the
        // cookie is visible on the next request.
        window.location.href = "/vault/";
        return;
      }
      setState({ phase: "idle" });
    })();
  }, []);

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setState({ phase: "working" });
    try {
      const user = await registerWithPasskey(email);
      setState({ phase: "done", email: user.email });
      setTimeout(() => {
        window.location.href = "/vault/";
      }, 800);
    } catch (err) {
      setState({
        phase: "error",
        message: err instanceof Error ? err.message : String(err),
      });
    }
  };

  return (
    <main className="mx-auto max-w-md px-6 py-16 text-slate-100">
      <h1 className="text-3xl font-bold mb-2">Create your vault</h1>
      <p className="text-sm text-slate-400 mb-8">
        One passkey. Your fingerprint or Face ID unlocks a quantum-secured
        vault. No password, no hex key, nothing to memorize.
      </p>

      <form onSubmit={onSubmit} className="space-y-4">
        <div>
          <label className="block text-xs font-medium text-slate-400 uppercase tracking-wide mb-1">
            Email
          </label>
          <input
            type="email"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="you@example.com"
            disabled={state.phase === "working" || state.phase === "done"}
            className="w-full bg-slate-900 border border-slate-800 rounded-lg p-3 text-sm"
          />
          <p className="text-xs text-slate-500 mt-1">
            Used only to sign you back in later. Your files are encrypted
            under your passkey — not your email.
          </p>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-lg p-3 text-xs text-slate-400 leading-relaxed">
          <b className="text-slate-300">Cross-browser tip:</b> when your
          browser asks where to save the passkey, choose{" "}
          <b className="text-slate-300">iCloud Keychain</b> (not Google
          Password Manager). iCloud syncs across Safari, Chrome, and
          every Apple device so you can sign in anywhere. Google Password
          Manager only works in Chrome.
        </div>

        <button
          type="submit"
          disabled={
            state.phase === "checking" ||
            state.phase === "working" ||
            state.phase === "done" ||
            !email
          }
          className="w-full rounded-lg bg-amber-500 text-slate-900 font-semibold px-5 py-3 text-sm disabled:opacity-30"
        >
          {state.phase === "checking" && "Checking browser support…"}
          {state.phase === "idle" && "Create passkey"}
          {state.phase === "working" && "Waiting for your authenticator…"}
          {state.phase === "done" && `Welcome, ${state.email}`}
          {state.phase === "error" && "Create passkey"}
        </button>
      </form>

      {state.phase === "error" && (
        <p className="mt-4 text-sm text-red-400 break-words">{state.message}</p>
      )}

      <p className="mt-8 text-xs text-slate-500 text-center">
        Already have a vault?{" "}
        <Link href="/login/" className="text-amber-400 hover:underline">
          Sign in
        </Link>
      </p>
    </main>
  );
}
