"use client";

import { useEffect, useState, useRef } from "react";
import Link from "next/link";
import {
  loginWithPasskey,
  loginWithPasskeyConditional,
  isPasskeySupported,
  fetchMe,
  loadMasterKey,
  saveMasterKey,
  reauthForMasterKey,
  ensureIdentity,
} from "../lib/passkey";
import {
  fetchRecoveryBlob,
  unwrapMasterKey,
  type RecoveryBlob,
} from "../lib/recovery";

// Login flow phases. The "passphrase" phase is reached when a
// passkey assertion succeeds but the authenticator doesn't return a
// PRF output (iOS Safari). The server has already issued a session
// cookie at this point, so we can download the recovery blob and
// prompt for the passphrase to unlock the master key.
type State =
  | { phase: "idle" }
  | { phase: "checking" }
  | { phase: "working" }
  | { phase: "unlock" }
  | { phase: "passphrase"; blob: RecoveryBlob }
  | { phase: "passphrase-error"; blob: RecoveryBlob; message: string }
  | { phase: "done" }
  | { phase: "error"; message: string };

export default function LoginPage() {
  const [email, setEmail] = useState("");
  const [state, setState] = useState<State>({ phase: "checking" });
  const [passphrase, setPassphrase] = useState("");
  const [passphraseBusy, setPassphraseBusy] = useState(false);
  const abortRef = useRef<AbortController | null>(null);

  /**
   * Called after any successful passkey ceremony that did NOT yield a
   * PRF output. Downloads the recovery blob and transitions to the
   * passphrase prompt, or to an error state explaining that the vault
   * has no passphrase set and must be unlocked from a PRF-capable
   * device first.
   */
  const fallbackToPassphrase = async (): Promise<void> => {
    try {
      const blob = await fetchRecoveryBlob();
      if (!blob) {
        setState({
          phase: "error",
          message:
            "This browser does not support the hardware passkey method RESQD uses, and this vault does not have a recovery passphrase set. Sign in from a Mac, PC, or Android with Touch ID / Windows Hello / fingerprint, open Settings → Recovery passphrase, and add one. You'll then be able to sign in here.",
        });
        return;
      }
      setState({ phase: "passphrase", blob });
    } catch (err) {
      setState({
        phase: "error",
        message:
          err instanceof Error
            ? `Could not fetch recovery blob: ${err.message}`
            : String(err),
      });
    }
  };

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
          // No PRF → passphrase fallback. The user IS signed in at
          // this point (session cookie set via login/finish_discoverable),
          // so downloading the recovery blob will work.
          await fallbackToPassphrase();
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
        // No PRF output — fall back to passphrase unlock. The session
        // cookie IS set at this point (login/finish ran regardless of
        // PRF), so we can download the recovery blob next.
        await fallbackToPassphrase();
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
        // reauth may fail because PRF isn't available on this device,
        // not because the user cancelled. Try the passphrase path
        // before giving up.
        await fallbackToPassphrase();
      }
    } catch (err) {
      setState({
        phase: "error",
        message: err instanceof Error ? err.message : String(err),
      });
    }
  };

  const onPassphraseSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (state.phase !== "passphrase" && state.phase !== "passphrase-error") {
      return;
    }
    setPassphraseBusy(true);
    try {
      const masterKey = await unwrapMasterKey(state.blob, passphrase);
      saveMasterKey(masterKey);
      // Best-effort identity mint/fetch. If this fails, sharing features
      // are degraded but the user's own vault is still accessible.
      await ensureIdentity(masterKey);
      setState({ phase: "done" });
      setTimeout(() => {
        window.location.href = "/vault/";
      }, 400);
    } catch (err) {
      setState({
        phase: "passphrase-error",
        blob: state.blob,
        message: err instanceof Error ? err.message : String(err),
      });
    } finally {
      setPassphraseBusy(false);
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

  if (state.phase === "passphrase" || state.phase === "passphrase-error") {
    return (
      <main className="mx-auto max-w-md px-6 py-16 text-slate-100">
        <h1 className="text-3xl font-bold mb-2">Unlock with passphrase</h1>
        <p className="text-sm text-slate-400 mb-6">
          This browser does not support the hardware passkey method
          RESQD uses on Mac / PC / Android. You&apos;re signed in — enter
          your recovery passphrase to unlock the vault.
        </p>

        <form onSubmit={onPassphraseSubmit} className="space-y-4">
          <div>
            <label className="block text-xs font-medium text-slate-400 uppercase tracking-wide mb-1">
              Recovery passphrase
            </label>
            <input
              type="password"
              required
              autoFocus
              value={passphrase}
              onChange={(e) => setPassphrase(e.target.value)}
              placeholder="Your passphrase"
              disabled={passphraseBusy}
              autoComplete="current-password"
              className="w-full bg-slate-900 border border-slate-800 rounded-lg p-3 text-sm font-mono"
            />
          </div>

          <button
            type="submit"
            disabled={passphraseBusy || passphrase.length === 0}
            className="w-full rounded-lg bg-amber-500 text-slate-900 font-semibold px-5 py-3 text-sm disabled:opacity-30"
          >
            {passphraseBusy ? "Deriving key…" : "Unlock vault"}
          </button>
        </form>

        {state.phase === "passphrase-error" && (
          <p className="mt-4 text-sm text-red-400 break-words">
            {state.message}
          </p>
        )}

        <div className="mt-8 bg-slate-900 border border-slate-800 rounded-lg p-3 text-xs text-slate-500 leading-relaxed">
          <b className="text-slate-400">Forgot your passphrase?</b> There
          is no reset. The vault is encrypted client-side and RESQD
          cannot see your keys. Sign in from a device with Touch ID /
          Windows Hello / fingerprint if you still have one — the
          hardware path works independently of the passphrase.
        </div>
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
