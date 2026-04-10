"use client";

import { useEffect, useState, useRef } from "react";
import Link from "next/link";
import {
  loginWithPasskey,
  loginWithPasskeyConditional,
  isPasskeySupported,
  fetchMe,
  loadMasterKey,
  reauthForMasterKey,
} from "../lib/passkey";

type State =
  | { phase: "idle" }
  | { phase: "checking" }
  | { phase: "working" }
  | { phase: "unlock" }
  | { phase: "done" }
  | { phase: "error"; message: string };

export default function LoginPage() {
  const [email, setEmail] = useState("");
  const [state, setState] = useState<State>({ phase: "checking" });
  const abortRef = useRef<AbortController | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    abortRef.current = controller;

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
        if (loadMasterKey()) {
          window.location.href = "/vault/";
          return;
        }
        // Valid session but no master key (sessionStorage cleared).
        // Show inline unlock prompt instead of redirecting to vault.
        setState({ phase: "unlock" });
        return;
      }
      setState({ phase: "idle" });

      // Kick off conditional-UI login in the background. The browser
      // will autofill passkey suggestions when the email field is
      // focused; selecting one completes the sign-in without the user
      // ever typing an email. If the user types and submits instead,
      // we abort this in `onSubmit` and fall through to the normal
      // typed-email flow.
      const user = await loginWithPasskeyConditional(controller.signal);
      if (user) {
        if (loadMasterKey()) {
          setState({ phase: "done" });
          window.location.href = "/vault/";
        } else {
          setState({
            phase: "error",
            message:
              "Signed in, but your browser does not support the PRF extension needed to derive your encryption key. Use Chrome or Safari on a Mac/PC — iOS does not support PRF yet.",
          });
        }
      }
    })();

    return () => {
      controller.abort();
    };
  }, []);

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    // Cancel the conditional-UI background listener so the explicit
    // typed-email flow can own the authenticator prompt.
    abortRef.current?.abort();
    setState({ phase: "working" });
    try {
      await loginWithPasskey(email);
      if (!loadMasterKey()) {
        setState({
          phase: "error",
          message:
            "Signed in, but your browser does not support the PRF extension needed to derive your encryption key. Use Chrome or Safari on a Mac/PC — iOS does not support PRF yet.",
        });
        return;
      }
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

  const onUnlock = async () => {
    setState({ phase: "working" });
    try {
      const ok = await reauthForMasterKey();
      if (ok) {
        setState({ phase: "done" });
        setTimeout(() => {
          window.location.href = "/vault/";
        }, 400);
      } else {
        setState({
          phase: "error",
          message: "Could not unlock — try signing in again.",
        });
      }
    } catch (err) {
      setState({
        phase: "error",
        message: err instanceof Error ? err.message : String(err),
      });
    }
  };

  if (state.phase === "unlock") {
    return (
      <main className="mx-auto max-w-md px-6 py-16 text-slate-100">
        <h1 className="text-3xl font-bold mb-2">Unlock your vault</h1>
        <p className="text-sm text-slate-400 mb-8">
          Your session is active but your encryption key needs to be re-derived.
          Tap below to authenticate with Touch ID.
        </p>
        <button
          onClick={onUnlock}
          className="w-full rounded-lg bg-amber-500 text-slate-900 font-semibold px-5 py-3 text-sm"
        >
          Unlock with Touch ID
        </button>
      </main>
    );
  }

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
            autoComplete="username webauthn"
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
