"use client";

/**
 * Placeholder billing page.
 *
 * Shows the user's "current tier" (always Trial in alpha) and an upgrade
 * matrix. There is no Stripe integration, no payment processing, no real
 * subscription state — the Upgrade buttons all show a dismissible notice
 * explaining billing is not yet enabled. The page exists so the product
 * feels like a product, and so the pricing model (see docs/BILLING.md)
 * is legible inside the app the same way it's legible on the landing.
 */

import { useEffect, useState } from "react";
import Link from "next/link";
import { fetchMe, type SessionUser } from "../lib/passkey";

interface Tier {
  key: string;
  name: string;
  price: string;
  cadence: string;
  tagline: string;
  storage: string;
  features: string[];
}

const TIERS: Tier[] = [
  {
    key: "trial",
    name: "Trial",
    price: "$0",
    cadence: "forever",
    tagline: "Full security stack, tiny capacity.",
    storage: "100 MB",
    features: [
      "Up to 50 assets",
      "Single user",
      "Post-quantum crypto",
      "Multi-cloud erasure coding",
      "On-chain canary anchoring",
      "Community support",
    ],
  },
  {
    key: "vault",
    name: "Vault",
    price: "$7.99",
    cadence: "/month",
    tagline: "For one person's digital life.",
    storage: "5 GB",
    features: [
      "Unlimited assets",
      "Single user",
      "Everything in Trial",
      "Email support (48h)",
      "MCP + API token access",
    ],
  },
  {
    key: "heirloom",
    name: "Heirloom",
    price: "$19.99",
    cadence: "/month",
    tagline: "Built for families and estates.",
    storage: "50 GB",
    features: [
      "Up to 5 family members",
      "Shared vault folders",
      "Estate triggers + scheduled unlock",
      "Everything in Vault",
      "Priority support (24h)",
    ],
  },
  {
    key: "custodian",
    name: "Custodian",
    price: "$99",
    cadence: "/month",
    tagline: "For regulated teams.",
    storage: "500 GB",
    features: [
      "Up to 25 seats",
      "SSO (OIDC / SAML)",
      "Audit log export",
      "99.9% SLA",
      "Dedicated support (4h)",
    ],
  },
];

export default function BillingPage() {
  const [user, setUser] = useState<SessionUser | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  // All alpha users are on Trial. This gets replaced with a real value
  // from the server once billing is wired up.
  const currentTier = "trial";

  useEffect(() => {
    (async () => {
      const me = await fetchMe();
      if (!me) {
        window.location.href = "/login/";
        return;
      }
      setUser(me);
    })();
  }, []);

  const onUpgrade = (tier: Tier) => {
    setNotice(
      `Billing isn't enabled in alpha — every user is on Trial with the full security stack. When we turn payments on, this button will take you to Stripe Checkout for ${tier.name} at ${tier.price}${tier.cadence}.`,
    );
  };

  return (
    <main className="mx-auto max-w-5xl px-6 py-12 text-slate-100">
      <header className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-3xl font-bold">Billing</h1>
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

      {/* Current tier card */}
      <section className="bg-slate-900 border border-slate-800 rounded-xl p-6 mb-10">
        <div className="flex items-center justify-between">
          <div>
            <div className="text-xs uppercase tracking-widest text-slate-500">
              Current plan
            </div>
            <h2 className="text-2xl font-bold mt-1">Trial</h2>
            <p className="text-sm text-slate-400 mt-1">
              Every alpha user is on Trial. You have the complete
              cryptographic stack — post-quantum encryption, multi-cloud
              storage, on-chain anchoring. No credit card on file.
            </p>
          </div>
          <div className="text-right">
            <div className="text-3xl font-bold text-amber-400">100 MB</div>
            <div className="text-xs text-slate-500">storage</div>
          </div>
        </div>
      </section>

      {/* Upgrade matrix */}
      <section>
        <h2 className="text-xl font-semibold mb-1">Upgrade</h2>
        <p className="text-xs text-slate-500 mb-6">
          Pricing is finalized but billing is not yet enabled. See the
          detailed rationale in <code className="text-slate-400">docs/BILLING.md</code>.
        </p>

        {notice && (
          <div className="mb-6 bg-amber-500/5 border border-amber-500/40 rounded-lg p-4 text-sm text-amber-100 flex items-start justify-between gap-4">
            <span>{notice}</span>
            <button
              onClick={() => setNotice(null)}
              className="text-xs text-amber-400 hover:text-amber-200 shrink-0"
            >
              Dismiss
            </button>
          </div>
        )}

        <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-4">
          {TIERS.map((t) => {
            const isCurrent = t.key === currentTier;
            return (
              <div
                key={t.key}
                className={`rounded-xl p-5 border flex flex-col ${
                  isCurrent
                    ? "bg-slate-900 border-amber-500/40"
                    : "bg-slate-900 border-slate-800"
                }`}
              >
                <h3 className="text-lg font-semibold">{t.name}</h3>
                <p className="text-xs text-slate-400 mt-1 mb-3">{t.tagline}</p>
                <div className="flex items-baseline gap-1 mb-1">
                  <span className="text-3xl font-bold">{t.price}</span>
                  <span className="text-sm text-slate-500">{t.cadence}</span>
                </div>
                <div className="text-xs text-amber-400 mb-4">
                  {t.storage} storage
                </div>
                <ul className="space-y-2 text-xs text-slate-300 flex-1 mb-5">
                  {t.features.map((f) => (
                    <li key={f} className="flex gap-2">
                      <span className="text-amber-400 shrink-0">✓</span>
                      <span>{f}</span>
                    </li>
                  ))}
                </ul>
                {isCurrent ? (
                  <div className="text-center rounded-lg border border-amber-500/40 py-2 text-xs text-amber-300">
                    Your plan
                  </div>
                ) : (
                  <button
                    onClick={() => onUpgrade(t)}
                    className="rounded-lg bg-amber-500 text-slate-900 font-semibold py-2 text-sm"
                  >
                    Upgrade
                  </button>
                )}
              </div>
            );
          })}
        </div>

        <p className="mt-8 text-xs text-slate-500 italic">
          Principle: RESQD never gates security features behind pricing
          tiers. Post-quantum crypto, multi-cloud storage, and on-chain
          anchoring are the same on every plan — you pay for capacity,
          not safety.
        </p>
      </section>
    </main>
  );
}
