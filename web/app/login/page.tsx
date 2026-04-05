"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  loginWithPasskey,
  isPasskeySupported,
  fetchMe,
} from "../lib/passkey";

type State =
  | { phase: "idle" }
  | { phase: "checking" }
  | { phase: "working" }
  | { phase: "done" }
  | { phase: "error"; message: string };

export default function LoginPage() {
  const [email, setEmail] = useState("");
  const [state, setState] = useState<State>({ phase: "checking" });

  useEffect(() => {
    (async () => {
      if (!isPasskeySupported()) {
        setState({
          phase: "error",
          message:
            "passkeys are not supported in this browser — try Chrome, Safari, or Edge",
        });
        return;
      }
      const me = await fetchMe();
      if (me) {
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
      await loginWithPasskey(email);
      setState({ phase: "done" });
      setTimeout(() => {
        window.location.href = "/vault/";
      }, 400);
    } catch (err) {
      setState({
        phase: "error",
        message: err instanceof Error ? err.message : String(err),
      });
    }
  };

  return (
    <main className="mx-auto max-w-md px-6 py-16 text-slate-100">
      <h1 className="text-3xl font-bold mb-2">Sign in</h1>
      <p className="text-sm text-slate-400 mb-8">
        Use the passkey you created at signup.
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
          {state.phase === "checking" && "Checking browser…"}
          {state.phase === "idle" && "Sign in with passkey"}
          {state.phase === "working" && "Waiting for your authenticator…"}
          {state.phase === "done" && "✓ Signed in"}
          {state.phase === "error" && "Sign in with passkey"}
        </button>
      </form>

      {state.phase === "error" && (
        <p className="mt-4 text-sm text-red-400 break-words">{state.message}</p>
      )}

      <p className="mt-8 text-xs text-slate-500 text-center">
        New to RESQD?{" "}
        <Link href="/signup/" className="text-amber-400 hover:underline">
          Create a vault
        </Link>
      </p>
    </main>
  );
}
