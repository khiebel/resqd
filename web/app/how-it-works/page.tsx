import Link from "next/link";

/**
 * Dedicated "How it works" page. Moved off the landing so the main
 * page is a focused hero → features → pricing flow; this lives at a
 * linkable URL for anyone who wants the step-by-step.
 */
export default function HowItWorksPage() {
  const steps = [
    {
      n: "01",
      title: "Sign up with a passkey",
      body: "Your fingerprint, Face ID, or Windows Hello creates a cryptographic identity bound to this device. Your vault key is derived from it via the WebAuthn PRF extension and never leaves the browser.",
    },
    {
      n: "02",
      title: "Drop a file",
      body: "The browser generates a fresh per-file key, encrypts your file with XChaCha20-Poly1305, seals that key under your master key, and Reed-Solomon codes the ciphertext into 6 shards.",
    },
    {
      n: "03",
      title: "Six clouds, one vault",
      body: "Each shard goes directly to a different storage backend via a presigned URL — RESQD's API never touches the bytes. No single cloud, or subpoena, can reconstruct your data. Any 4 of 6 shards is enough to recover.",
    },
    {
      n: "04",
      title: "Anchored on-chain",
      body: "Every access rotates a canary commitment and writes it to Base L2. You can verify the read history cryptographically, forever, for less than a penny per access. If anyone — including us — reads a file without your knowledge, the on-chain sequence proves it.",
    },
  ];

  return (
    <main className="min-h-screen bg-black text-slate-100">
      <nav className="sticky top-0 z-20 backdrop-blur bg-black/70 border-b border-slate-900">
        <div className="mx-auto max-w-4xl px-6 py-4 flex items-center justify-between">
          <Link href="/" className="font-bold tracking-tight text-lg">
            RESQD
          </Link>
          <div className="flex items-center gap-6 text-sm text-slate-400">
            <Link href="/why/" className="hover:text-slate-100">
              Why RESQD
            </Link>
            <Link href="/how-it-works/" className="text-slate-100">
              How it works
            </Link>
            <Link href="/signup/" className="rounded-lg bg-amber-500 text-slate-900 font-semibold px-4 py-2">
              Sign up
            </Link>
          </div>
        </div>
      </nav>

      <article className="mx-auto max-w-3xl px-6 py-16">
        <header className="mb-16 text-center">
          <p className="text-xs uppercase tracking-widest text-amber-500 mb-3">
            Four steps. Every step in your browser.
          </p>
          <h1 className="text-4xl md:text-5xl font-bold mb-4">How it works</h1>
          <p className="text-slate-400 max-w-xl mx-auto leading-relaxed">
            Every step happens on your device before a single byte
            reaches our servers. The RESQD API is zero-knowledge by
            architecture — not by promise.
          </p>
        </header>

        <div className="space-y-12">
          {steps.map((s) => (
            <div key={s.n} className="flex gap-8 items-start">
              <div className="text-5xl font-mono bg-gradient-to-b from-amber-300 to-violet-500 bg-clip-text text-transparent shrink-0 w-20">
                {s.n}
              </div>
              <div className="flex-1 border-l border-slate-800 pl-8">
                <h2 className="text-xl font-semibold mb-2">{s.title}</h2>
                <p className="text-slate-400 leading-relaxed">{s.body}</p>
              </div>
            </div>
          ))}
        </div>

        <div className="mt-16 border-t border-slate-900 pt-12 text-center">
          <p className="text-sm text-slate-400 mb-6">
            For the specific cryptographic primitives and trust
            boundaries, read the{" "}
            <Link
              href="/security-model/"
              className="text-amber-400 hover:underline"
            >
              Security Model
            </Link>
            .
          </p>
          <Link
            href="/signup/"
            className="inline-block rounded-lg bg-amber-500 hover:bg-amber-400 text-slate-900 font-semibold px-8 py-4 text-sm transition-colors"
          >
            Create your vault — free
          </Link>
        </div>
      </article>
    </main>
  );
}
