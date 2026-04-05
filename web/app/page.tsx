import Link from "next/link";

/**
 * RESQD landing page.
 *
 * This page is the first impression anyone lands on. Its job is to get
 * two audiences to sign up:
 *
 *   1. Security-literate users who will grok "post-quantum + zero-knowledge
 *      + on-chain canary anchoring" and want to try it.
 *   2. Families and individuals with high-value digital assets (tax returns,
 *      crypto keys, estate documents, medical records) who need the promise
 *      to be legible without the jargon.
 *
 * Structure: hero → proof points → how it works → pricing → CTA. Pricing
 * is a placeholder — see docs/BILLING.md for the rationale and real
 * numbers. Nothing on this page is fake-except where marked "alpha".
 */
export default function Home() {
  return (
    <main className="min-h-screen bg-black text-slate-100">
      <TopNav />
      <Hero />
      <FeatureGrid />
      <HowItWorks />
      <Pricing />
      <TrustMarkers />
      <FinalCta />
      <Footer />
    </main>
  );
}

function TopNav() {
  return (
    <nav className="sticky top-0 z-20 backdrop-blur bg-black/70 border-b border-slate-900">
      <div className="mx-auto max-w-6xl px-6 py-4 flex items-center justify-between">
        <Link href="/" className="font-bold tracking-tight text-lg">
          RESQD
          <span className="ml-2 text-[10px] uppercase tracking-widest text-amber-500 align-middle">
            alpha
          </span>
        </Link>
        <div className="flex items-center gap-6 text-sm text-slate-400">
          <a href="#how" className="hover:text-slate-100">How it works</a>
          <a href="#pricing" className="hover:text-slate-100">Pricing</a>
          <Link href="/login/" className="hover:text-slate-100">Sign in</Link>
          <Link
            href="/signup/"
            className="rounded-lg bg-amber-500 text-slate-900 font-semibold px-4 py-2"
          >
            Create a vault
          </Link>
        </div>
      </div>
    </nav>
  );
}

function Hero() {
  return (
    <section className="mx-auto max-w-5xl px-6 pt-24 pb-20 text-center">
      <p className="text-xs uppercase tracking-widest text-amber-500 mb-6">
        Post-quantum · Multi-cloud · Tamper-evident
      </p>
      <h1 className="text-5xl md:text-6xl font-bold tracking-tight leading-[1.05]">
        Your digital life,
        <br />
        <span className="text-amber-400">rescued.</span>
      </h1>
      <p className="mt-8 text-lg text-slate-400 max-w-2xl mx-auto leading-relaxed">
        RESQD is a zero-knowledge vault for the things that matter most —
        tax returns, medical records, recovery phrases, family archives.
        Encrypted in your browser with post-quantum crypto, sharded across
        three clouds, and every access cryptographically sealed on a
        public blockchain. Even we can&apos;t read what you store.
      </p>
      <div className="mt-10 flex items-center justify-center gap-4">
        <Link
          href="/signup/"
          className="rounded-lg bg-amber-500 text-slate-900 font-semibold px-8 py-4 text-sm"
        >
          Create your vault — free
        </Link>
        <a
          href="#how"
          className="rounded-lg border border-slate-700 hover:border-slate-500 px-8 py-4 text-sm text-slate-300"
        >
          How it works
        </a>
      </div>
      <p className="mt-6 text-xs text-slate-600">
        No credit card. No password. Sign up with your fingerprint.
      </p>
    </section>
  );
}

function FeatureGrid() {
  const features = [
    {
      title: "Post-quantum encryption",
      body: "ML-KEM-768 key exchange and XChaCha20-Poly1305 AEAD. Every tier, not just enterprise. When quantum computers arrive, your vault doesn't need to be migrated.",
    },
    {
      title: "Zero knowledge, by architecture",
      body: "Your files are encrypted in the browser before they ever leave your device. RESQD servers store ciphertext, wrapped keys, and opaque metadata — we literally cannot read your data.",
    },
    {
      title: "Multi-cloud erasure coding",
      body: "Every file is Reed-Solomon coded into 6 shards spread across AWS, Google Cloud, and Azure. Any cloud can disappear and your data is intact. Any 4 of 6 shards reconstruct the original.",
    },
    {
      title: "Tamper-evident by default",
      body: "Every read rotates a cryptographic canary and anchors the new commitment on Base L2. If anyone — including us — accesses a file without you, the on-chain record proves it.",
    },
    {
      title: "Passkey-native",
      body: "No passwords, no hex keys, no backup phrases. Your encryption key is derived from your passkey via WebAuthn PRF. It never touches a server and never leaves your device.",
    },
    {
      title: "AI-agent ready",
      body: "First-class MCP server for Claude and other LLM agents. Let AI tools read and write your vault under scoped, revocable credentials — without breaking zero-knowledge.",
    },
  ];
  return (
    <section className="border-y border-slate-900 bg-slate-950">
      <div className="mx-auto max-w-6xl px-6 py-20">
        <h2 className="text-3xl font-bold text-center mb-4">
          Every feature. Every tier. No gatekeeping on safety.
        </h2>
        <p className="text-center text-slate-400 max-w-2xl mx-auto mb-14">
          We never charge for security. Post-quantum crypto, multi-cloud
          storage, and on-chain anchoring are the same whether you&apos;re
          free or enterprise.
        </p>
        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-4">
          {features.map((f) => (
            <div
              key={f.title}
              className="bg-slate-900 border border-slate-800 rounded-xl p-6 hover:border-slate-700 transition-colors"
            >
              <h3 className="text-lg font-semibold mb-2">{f.title}</h3>
              <p className="text-sm text-slate-400 leading-relaxed">{f.body}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

function HowItWorks() {
  const steps = [
    {
      n: "01",
      title: "Sign up with a passkey",
      body: "Your fingerprint, Face ID, or Windows Hello creates a cryptographic identity bound to this device. Your vault key is derived from it and never leaves the browser.",
    },
    {
      n: "02",
      title: "Drop a file",
      body: "The browser generates a fresh per-file key, encrypts your file, seals that key under your master key, and Reed-Solomon codes the ciphertext into 6 shards.",
    },
    {
      n: "03",
      title: "Six clouds, one vault",
      body: "Each shard goes to a different storage backend. No single cloud — or subpoena — can reconstruct your data. Any 4 of 6 shards is enough to recover.",
    },
    {
      n: "04",
      title: "Anchored on-chain",
      body: "Every access rotates a canary commitment and writes it to Base L2. You can verify the read history cryptographically, forever, for less than a penny per access.",
    },
  ];
  return (
    <section id="how" className="mx-auto max-w-5xl px-6 py-24">
      <h2 className="text-3xl font-bold text-center mb-16">How it works</h2>
      <div className="space-y-12">
        {steps.map((s) => (
          <div key={s.n} className="flex gap-8 items-start">
            <div className="text-4xl font-mono text-amber-500 shrink-0 w-16">
              {s.n}
            </div>
            <div className="flex-1 border-l border-slate-800 pl-8">
              <h3 className="text-xl font-semibold mb-2">{s.title}</h3>
              <p className="text-slate-400 leading-relaxed">{s.body}</p>
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}

function Pricing() {
  const tiers = [
    {
      name: "Trial",
      price: "$0",
      cadence: "forever",
      tagline: "Full security stack, tiny capacity.",
      features: [
        "100 MB storage",
        "Up to 50 assets",
        "Single user",
        "Community support",
      ],
      cta: "Start free",
      highlight: false,
    },
    {
      name: "Vault",
      price: "$7.99",
      cadence: "/month",
      tagline: "For one person's digital life.",
      features: [
        "5 GB storage",
        "Unlimited assets",
        "Email support (48h)",
        "Passkey + hardware key",
        "MCP / API access",
      ],
      cta: "Choose Vault",
      highlight: false,
    },
    {
      name: "Heirloom",
      price: "$19.99",
      cadence: "/month",
      tagline: "Built for families and estates.",
      features: [
        "50 GB storage",
        "Up to 5 family members",
        "Estate triggers & scheduled unlock",
        "Shared vault folders",
        "Priority support (24h)",
      ],
      cta: "Choose Heirloom",
      highlight: true,
    },
    {
      name: "Custodian",
      price: "$99",
      cadence: "/month",
      tagline: "For regulated teams.",
      features: [
        "500 GB pooled storage",
        "Up to 25 seats",
        "SSO (OIDC / SAML)",
        "Audit log export",
        "99.9% SLA",
      ],
      cta: "Contact sales",
      highlight: false,
    },
  ];
  return (
    <section
      id="pricing"
      className="border-y border-slate-900 bg-gradient-to-b from-slate-950 to-black"
    >
      <div className="mx-auto max-w-6xl px-6 py-24">
        <h2 className="text-3xl font-bold text-center mb-3">
          Pay for capacity. Never for safety.
        </h2>
        <p className="text-center text-slate-400 max-w-2xl mx-auto mb-4">
          Every tier gets the complete cryptographic stack — post-quantum
          encryption, multi-cloud storage, and on-chain anchoring. You
          upgrade for storage, seats, and convenience features.
        </p>
        <p className="text-center text-xs text-slate-600 mb-14">
          Alpha: billing is not yet enabled. All users are on Trial.
        </p>
        <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-4">
          {tiers.map((t) => (
            <div
              key={t.name}
              className={`rounded-xl p-6 border ${
                t.highlight
                  ? "bg-amber-500/5 border-amber-500/40 relative"
                  : "bg-slate-900 border-slate-800"
              }`}
            >
              {t.highlight && (
                <div className="absolute -top-3 left-1/2 -translate-x-1/2 bg-amber-500 text-slate-900 text-xs font-semibold px-3 py-1 rounded-full">
                  Most popular
                </div>
              )}
              <h3 className="text-lg font-semibold">{t.name}</h3>
              <p className="text-xs text-slate-400 mt-1 mb-4">{t.tagline}</p>
              <div className="flex items-baseline gap-1 mb-6">
                <span className="text-4xl font-bold">{t.price}</span>
                <span className="text-sm text-slate-500">{t.cadence}</span>
              </div>
              <ul className="space-y-2 text-sm text-slate-300 mb-8">
                {t.features.map((f) => (
                  <li key={f} className="flex gap-2">
                    <span className="text-amber-400">✓</span>
                    <span>{f}</span>
                  </li>
                ))}
              </ul>
              <Link
                href="/signup/"
                className={`block text-center rounded-lg py-2.5 text-sm font-semibold ${
                  t.highlight
                    ? "bg-amber-500 text-slate-900"
                    : "border border-slate-700 hover:border-slate-500"
                }`}
              >
                {t.cta}
              </Link>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

function TrustMarkers() {
  return (
    <section className="mx-auto max-w-5xl px-6 py-20">
      <div className="grid md:grid-cols-3 gap-6 text-center">
        <div>
          <div className="text-3xl font-bold text-amber-400 mb-1">
            ML-KEM-768
          </div>
          <div className="text-sm text-slate-400">
            NIST-standardized post-quantum key encapsulation
          </div>
        </div>
        <div>
          <div className="text-3xl font-bold text-amber-400 mb-1">
            4-of-6 shards
          </div>
          <div className="text-sm text-slate-400">
            Reed-Solomon erasure coding across three cloud providers
          </div>
        </div>
        <div>
          <div className="text-3xl font-bold text-amber-400 mb-1">
            On-chain
          </div>
          <div className="text-sm text-slate-400">
            Every access anchored to Base L2 for cryptographic tamper evidence
          </div>
        </div>
      </div>
    </section>
  );
}

function FinalCta() {
  return (
    <section className="border-t border-slate-900 bg-slate-950">
      <div className="mx-auto max-w-3xl px-6 py-20 text-center">
        <h2 className="text-3xl font-bold mb-3">
          Start with your hardest secret.
        </h2>
        <p className="text-slate-400 mb-8">
          The thing you&apos;d be most devastated to lose — back it up to a
          vault that was designed assuming everyone except you is hostile.
        </p>
        <Link
          href="/signup/"
          className="inline-block rounded-lg bg-amber-500 text-slate-900 font-semibold px-8 py-4"
        >
          Create your vault
        </Link>
      </div>
    </section>
  );
}

function Footer() {
  return (
    <footer className="border-t border-slate-900 text-xs text-slate-500">
      <div className="mx-auto max-w-6xl px-6 py-8 flex flex-wrap items-center justify-between gap-4">
        <div>© 2026 RESQD. All rights reserved.</div>
        <div className="flex gap-6">
          <a href="#how" className="hover:text-slate-300">How it works</a>
          <a href="#pricing" className="hover:text-slate-300">Pricing</a>
          <span className="text-slate-700">·</span>
          <Link href="/login/" className="hover:text-slate-300">Sign in</Link>
        </div>
      </div>
    </footer>
  );
}
