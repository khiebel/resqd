import Link from "next/link";
import Image from "next/image";
// Image is used only in TopNav for the logo now that the hero image
// has been removed. Keeping the import rather than inlining an <img>
// so Next's image optimizer still handles it.

/**
 * RESQD landing — the canonical marketing + signup page served at
 * resqd.ai. Single source of truth for everything a visitor sees
 * before signing in: hero, proof bar, features, how-it-works, pitch,
 * pricing, trust markers, legal links. The app surface (signup, login,
 * vault, settings, billing) lives alongside this page in the same
 * Next.js app, so the user journey from "landed on resqd.ai" to "just
 * uploaded my first file" stays inside one deployment.
 *
 * Content is ported from the old static `site/index.html` with the
 * waitlist forms replaced by direct signup CTAs. Visual language is
 * deliberately a blend: the app's amber/slate palette (for consistency
 * with what users see after sign-in) plus gradient accents in the hero
 * to signal the crypto/quantum positioning.
 */

export default function Home() {
  return (
    <main className="min-h-screen bg-black text-slate-100">
      <TopNav />
      <Hero />
      <StatsBar />
      <FeatureGrid />
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
        <Link href="/" className="flex items-center gap-2.5">
          <Image
            src="/marketing/icon.png"
            alt="RESQD"
            width={32}
            height={32}
            className="rounded-md"
          />
          <span className="font-bold tracking-tight text-lg">
            RESQD
            <span className="ml-2 text-[10px] uppercase tracking-widest text-amber-500 align-middle">
              alpha
            </span>
          </span>
        </Link>
        <div className="flex items-center gap-6 text-sm text-slate-400">
          <Link href="/why/" className="hover:text-slate-100 hidden md:inline">
            Why RESQD
          </Link>
          <Link
            href="/how-it-works/"
            className="hover:text-slate-100 hidden md:inline"
          >
            How it works
          </Link>
          <a href="#pricing" className="hover:text-slate-100 hidden md:inline">
            Pricing
          </a>
          <Link href="/login/" className="hover:text-slate-100">
            Sign in
          </Link>
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
    <section className="relative overflow-hidden">
      {/* Gradient glows */}
      <div className="absolute inset-0 pointer-events-none">
        <div className="absolute top-0 left-1/4 w-[600px] h-[600px] rounded-full bg-amber-500/10 blur-3xl" />
        <div className="absolute top-32 right-1/4 w-[500px] h-[500px] rounded-full bg-violet-600/10 blur-3xl" />
      </div>

      <div className="relative mx-auto max-w-5xl px-6 pt-24 pb-16 text-center">
        <p className="text-xs uppercase tracking-widest text-amber-500 mb-6">
          Post-quantum · Multi-cloud · Tamper-evident
        </p>
        <h1 className="text-5xl md:text-7xl font-bold tracking-tight leading-[1.05]">
          Your digital life,
          <br />
          <span className="bg-gradient-to-r from-amber-300 via-amber-400 to-violet-400 bg-clip-text text-transparent">
            rescued.
          </span>
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
            className="rounded-lg bg-amber-500 hover:bg-amber-400 text-slate-900 font-semibold px-8 py-4 text-sm transition-colors"
          >
            Create your vault — free
          </Link>
          <Link
            href="/how-it-works/"
            className="rounded-lg border border-slate-700 hover:border-slate-500 px-8 py-4 text-sm text-slate-300 transition-colors"
          >
            How it works
          </Link>
        </div>
        <p className="mt-6 text-xs text-slate-600">
          No credit card. No password. Sign up with your fingerprint.
        </p>
      </div>
    </section>
  );
}

function StatsBar() {
  const stats = [
    { num: "3", label: "Cloud providers" },
    { num: "PQ", label: "Post-quantum crypto" },
    { num: "0", label: "Single points of failure" },
    { num: "∞", label: "Verifiable access history" },
  ];
  return (
    <section className="border-y border-slate-900">
      <div className="mx-auto max-w-5xl px-6 py-10">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-8 text-center">
          {stats.map((s) => (
            <div key={s.label}>
              <div className="text-3xl md:text-4xl font-bold bg-gradient-to-r from-amber-300 to-violet-400 bg-clip-text text-transparent">
                {s.num}
              </div>
              <div className="text-xs text-slate-500 mt-1 uppercase tracking-wide">
                {s.label}
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

function FeatureGrid() {
  const features: {
    title: string;
    body: string;
    link?: { href: string; label: string };
  }[] = [
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
      link: { href: "/mcp/", label: "Connect Claude →" },
    },
  ];
  return (
    <section className="border-b border-slate-900 bg-slate-950">
      <div className="mx-auto max-w-6xl px-6 py-24">
        <h2 className="text-3xl md:text-4xl font-bold text-center mb-4">
          Every feature. Every tier. No gatekeeping on safety.
        </h2>
        <p className="text-center text-slate-400 max-w-2xl mx-auto mb-14">
          We never charge for security. Post-quantum crypto, multi-cloud
          storage, and on-chain anchoring are the same whether you&apos;re
          on free or enterprise.
        </p>
        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-4">
          {features.map((f) => (
            <div
              key={f.title}
              className="bg-slate-900 border border-slate-800 rounded-xl p-6 hover:border-amber-500/40 transition-colors flex flex-col"
            >
              <h3 className="text-lg font-semibold mb-2">{f.title}</h3>
              <p className="text-sm text-slate-400 leading-relaxed flex-1">
                {f.body}
              </p>
              {f.link && (
                <Link
                  href={f.link.href}
                  className="mt-3 text-xs text-amber-400 hover:underline"
                >
                  {f.link.label}
                </Link>
              )}
            </div>
          ))}
        </div>
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
        "Family rings with Owner / Adult / Child / Executor roles",
        "Estate triggers — inactivity or scheduled unlock for heirs",
        "Read-only asset sharing + ring-owned uploads",
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
    <section id="pricing" className="bg-gradient-to-b from-black to-slate-950">
      <div className="mx-auto max-w-6xl px-6 py-24">
        <h2 className="text-3xl md:text-4xl font-bold text-center mb-3">
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
              className={`rounded-xl p-6 border flex flex-col ${
                t.highlight
                  ? "bg-gradient-to-b from-amber-500/10 to-transparent border-amber-500/40 relative"
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
              <ul className="space-y-2 text-sm text-slate-300 mb-8 flex-1">
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
            Every access anchored to Base L2 for cryptographic tamper
            evidence
          </div>
        </div>
      </div>
    </section>
  );
}

function FinalCta() {
  return (
    <section className="border-t border-slate-900 bg-slate-950">
      <div className="mx-auto max-w-3xl px-6 py-24 text-center">
        <h2 className="text-3xl md:text-4xl font-bold mb-3">
          Start with your hardest secret.
        </h2>
        <p className="text-slate-400 mb-10 leading-relaxed">
          The thing you&apos;d be most devastated to lose — back it up to a
          vault that was designed assuming everyone except you is hostile.
          Alpha is open. Takes under a minute.
        </p>
        <Link
          href="/signup/"
          className="inline-block rounded-lg bg-amber-500 hover:bg-amber-400 text-slate-900 font-semibold px-8 py-4 transition-colors"
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
      <div className="mx-auto max-w-6xl px-6 py-10">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>© 2026 RESQD · Quantum-secured digital vault</div>
          <div className="flex gap-5 flex-wrap">
            <Link href="/why/" className="hover:text-slate-300">
              Why RESQD
            </Link>
            <Link href="/how-it-works/" className="hover:text-slate-300">
              How it works
            </Link>
            <a href="#pricing" className="hover:text-slate-300">Pricing</a>
            <Link href="/security-model/" className="hover:text-slate-300">
              Security
            </Link>
            <Link href="/privacy/" className="hover:text-slate-300">
              Privacy
            </Link>
            <Link href="/terms/" className="hover:text-slate-300">
              Terms
            </Link>
          </div>
        </div>
        <p className="mt-4 text-slate-600">
          Built with post-quantum cryptography. Your secrets stay secret —
          forever.
        </p>
      </div>
    </footer>
  );
}
