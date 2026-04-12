"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  registerWithPasskey,
  isPasskeySupported,
  fetchMe,
  loadMasterKey,
  saveMasterKey,
  ensureIdentity,
} from "../lib/passkey";
import {
  setRecoveryPassphrase,
  estimatePassphraseStrength,
  MIN_PASSPHRASE_LENGTH,
} from "../lib/recovery";
import { getCrypto } from "../lib/resqdCrypto";

// Signup phases. "passphrase" is entered when a PRF-capable
// browser cannot produce a PRF output — the server issued the
// session cookie at this point, but there's no master key, so we
// need the user to pick a passphrase that will wrap a fresh random
// master key before we let them into the vault.
type State =
  | { phase: "idle" }
  | { phase: "checking" }
  | { phase: "working" }
  | { phase: "passphrase"; email: string }
  | { phase: "wrapping"; email: string }
  | { phase: "done"; email: string }
  | { phase: "error"; message: string };

export default function SignupPage() {
  const [email, setEmail] = useState("");
  const [state, setState] = useState<State>({ phase: "checking" });

  // Passphrase form state, used only in the "passphrase" phase.
  const [passphrase, setPassphrase] = useState("");
  const [passphraseConfirm, setPassphraseConfirm] = useState("");
  const [passphraseRevealed, setPassphraseRevealed] = useState(false);
  const [passphraseError, setPassphraseError] = useState<string | null>(null);
  const passphraseStrength = estimatePassphraseStrength(passphrase);
  const passphrasesMatch =
    passphrase.length > 0 && passphrase === passphraseConfirm;
  const canSubmitPassphrase =
    passphraseStrength.meetsMinimum && passphrasesMatch;

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
      // If PRF is available, `registerWithPasskey` already stashed
      // the master key in sessionStorage. Proceed to vault directly.
      if (loadMasterKey()) {
        setState({ phase: "done", email: user.email });
        setTimeout(() => {
          window.location.href = "/vault/";
        }, 800);
        return;
      }
      // No PRF. User has a session cookie but no master key yet.
      // Route into the passphrase-setup flow — they'll pick a
      // passphrase that wraps a fresh random master key.
      setState({ phase: "passphrase", email: user.email });
    } catch (err) {
      setState({
        phase: "error",
        message: err instanceof Error ? err.message : String(err),
      });
    }
  };

  /**
   * Finalize an iPhone signup: generate a random master key, wrap it
   * under the chosen passphrase, and upload the recovery blob.
   * `registerWithPasskey` has already run — the session cookie is
   * set and the account row exists on the server; all we're doing
   * here is seeding the key material.
   */
  const onPassphraseSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (state.phase !== "passphrase") return;
    setPassphraseError(null);

    if (!passphraseStrength.meetsMinimum) {
      setPassphraseError(
        `Passphrase must be at least ${MIN_PASSPHRASE_LENGTH} characters.`,
      );
      return;
    }
    if (!passphrasesMatch) {
      setPassphraseError("Passphrases do not match.");
      return;
    }

    setState({ phase: "wrapping", email: state.email });
    try {
      const crypto = await getCrypto();
      // Fresh 32-byte random master key. Lives only in memory — the
      // plaintext never touches the server. We'll stash it in
      // sessionStorage after the wrap succeeds.
      const masterKey = crypto.generate_random_key();
      await setRecoveryPassphrase(passphrase, masterKey);
      saveMasterKey(masterKey);
      // Best-effort identity mint. Sharing/rings require this but
      // single-user vault ops don't, so a failure here is non-fatal.
      await ensureIdentity(masterKey);
      setState({ phase: "done", email: state.email });
      setTimeout(() => {
        window.location.href = "/vault/";
      }, 800);
    } catch (err) {
      setPassphraseError(
        err instanceof Error ? err.message : String(err),
      );
      setState({ phase: "passphrase", email: state.email });
    }
  };

  if (state.phase === "passphrase" || state.phase === "wrapping") {
    const busy = state.phase === "wrapping";
    return (
      <main className="mx-auto max-w-md px-6 py-16 text-slate-100">
        <h1 className="text-3xl font-bold mb-2">Pick a recovery passphrase</h1>
        <p className="text-sm text-slate-400 mb-6">
          Your passkey is saved, but your browser can&apos;t use the hardware
          encryption method RESQD normally uses. You&apos;ll unlock your vault
          on this device with a passphrase instead. <b>Read this carefully
            before you continue.</b>
        </p>

        <div className="bg-amber-950/30 border border-amber-900 rounded-lg p-4 mb-6 text-xs text-amber-200 leading-relaxed space-y-2">
          <p className="font-semibold text-amber-100">
            Passphrase mode is less secure than hardware passkey mode
          </p>
          <ul className="list-disc list-inside space-y-1">
            <li>
              On a Mac, PC, or Android, RESQD derives your master key
              inside your device&apos;s secure hardware. An attacker who
              steals your session cannot decrypt your files without
              your biometric.
            </li>
            <li>
              On iPhone Safari, RESQD cannot access that hardware. Your
              master key will be derived from this passphrase. An
              attacker who learns your passphrase — via a breach,
              keylogger, or shoulder-surfing — can decrypt everything.
            </li>
            <li>
              <b>If you forget your passphrase, your data is
                unrecoverable.</b>{" "}
              RESQD has no password reset. The whole point of the vault
              is that we can&apos;t see your keys.
            </li>
          </ul>
          <p className="font-semibold text-amber-100 mt-3">Recommended:</p>
          <ul className="list-disc list-inside space-y-1">
            <li>
              Use a password manager (1Password, Bitwarden, iCloud
              Keychain) to generate a <b>20+ character random
                passphrase</b>. Save it in the manager.
            </li>
            <li>
              When you can, sign in from a Mac, PC, or Android with
              Touch ID / Windows Hello / fingerprint — those devices
              use the stronger hardware path automatically.
            </li>
            <li>
              Print your Recovery Kit (from Settings, after your first
              upload) as an offline backup independent of your
              passphrase.
            </li>
          </ul>
        </div>

        <form onSubmit={onPassphraseSubmit} className="space-y-4">
          <div>
            <label className="block text-xs font-medium text-slate-400 uppercase tracking-wide mb-1">
              Passphrase
            </label>
            <div className="relative">
              <input
                type={passphraseRevealed ? "text" : "password"}
                value={passphrase}
                onChange={(e) => setPassphrase(e.target.value)}
                placeholder={`At least ${MIN_PASSPHRASE_LENGTH} characters`}
                disabled={busy}
                autoComplete="new-password"
                autoFocus
                className="w-full bg-slate-900 border border-slate-800 rounded-lg p-3 text-sm font-mono"
              />
              <button
                type="button"
                onClick={() => setPassphraseRevealed(!passphraseRevealed)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-xs text-slate-500 hover:text-slate-300"
                tabIndex={-1}
              >
                {passphraseRevealed ? "Hide" : "Show"}
              </button>
            </div>

            {passphrase.length > 0 && (
              <div className="mt-2">
                <div className="flex gap-1 h-1">
                  {[1, 2, 3, 4].map((bar) => (
                    <div
                      key={bar}
                      className={`flex-1 rounded ${
                        bar <= passphraseStrength.score
                          ? passphraseStrength.score <= 1
                            ? "bg-red-500"
                            : passphraseStrength.score === 2
                              ? "bg-yellow-500"
                              : passphraseStrength.score === 3
                                ? "bg-lime-500"
                                : "bg-green-500"
                          : "bg-slate-800"
                      }`}
                    />
                  ))}
                </div>
                <div className="flex justify-between mt-1 text-xs">
                  <span
                    className={
                      passphraseStrength.meetsMinimum
                        ? "text-slate-400"
                        : "text-red-400"
                    }
                  >
                    {passphraseStrength.label}
                  </span>
                  <span className="text-slate-500">
                    ~{passphraseStrength.bits} bits
                  </span>
                </div>
              </div>
            )}
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-400 uppercase tracking-wide mb-1">
              Confirm passphrase
            </label>
            <input
              type={passphraseRevealed ? "text" : "password"}
              value={passphraseConfirm}
              onChange={(e) => setPassphraseConfirm(e.target.value)}
              placeholder="Type it again"
              disabled={busy}
              autoComplete="new-password"
              className="w-full bg-slate-900 border border-slate-800 rounded-lg p-3 text-sm font-mono"
            />
            {passphraseConfirm.length > 0 && !passphrasesMatch && (
              <p className="mt-1 text-xs text-red-400">
                Passphrases do not match.
              </p>
            )}
          </div>

          {passphraseError && (
            <p className="text-sm text-red-400 break-words">{passphraseError}</p>
          )}

          <button
            type="submit"
            disabled={busy || !canSubmitPassphrase}
            className="w-full rounded-lg bg-amber-500 text-slate-900 font-semibold px-5 py-3 text-sm disabled:opacity-30"
          >
            {busy ? "Wrapping master key…" : "Create vault"}
          </button>
        </form>
      </main>
    );
  }

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
