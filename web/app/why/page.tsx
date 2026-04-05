import Link from "next/link";

/**
 * "Why the world needs RESQD" — the long-form pitch. Lives at a
 * dedicated URL so the main landing stays focused on hero + features
 * + pricing. Linked from the top nav and the footer.
 */
export default function WhyPage() {
  return (
    <main className="min-h-screen bg-black text-slate-100">
      <nav className="sticky top-0 z-20 backdrop-blur bg-black/70 border-b border-slate-900">
        <div className="mx-auto max-w-4xl px-6 py-4 flex items-center justify-between">
          <Link href="/" className="font-bold tracking-tight text-lg">
            RESQD
          </Link>
          <div className="flex items-center gap-6 text-sm text-slate-400">
            <Link href="/how-it-works/" className="hover:text-slate-100">
              How it works
            </Link>
            <Link href="/why/" className="text-slate-100">
              Why RESQD
            </Link>
            <Link
              href="/signup/"
              className="rounded-lg bg-amber-500 text-slate-900 font-semibold px-4 py-2"
            >
              Sign up
            </Link>
          </div>
        </div>
      </nav>

      <article className="mx-auto max-w-3xl px-6 py-16">
        <header className="mb-12">
          <p className="text-xs uppercase tracking-widest text-amber-500 mb-3">
            The argument
          </p>
          <h1 className="text-4xl md:text-5xl font-bold mb-6 bg-gradient-to-r from-amber-300 to-violet-400 bg-clip-text text-transparent">
            Why the world needs RESQD
          </h1>
        </header>

        <div className="space-y-6 text-slate-300 leading-relaxed text-base">
          <p>
            Every day, families lose irreplaceable photos to cloud
            provider outages. Businesses lose millions to data breaches
            that silently exfiltrate secrets for months before detection.
            Crypto holders die without their heirs knowing how to access
            their wallets. And{" "}
            <span className="text-slate-100 font-semibold">
              quantum computers are coming
            </span>{" "}
            — rendering today&apos;s encryption obsolete within the
            decade.
          </p>

          <p>
            The solutions people use today are dangerously fragile.
            iCloud? One account compromise and everything is gone.
            Google Drive? A single company controls your memories. A
            password manager? It stores credentials, not your life&apos;s
            work. An encrypted USB drive? One hardware failure from
            total loss.
          </p>

          <p>
            <span className="text-slate-100 font-semibold">
              RESQD is different.
            </span>{" "}
            We don&apos;t store your data — we rescue it. Your files
            are encrypted with post-quantum algorithms{" "}
            <em className="text-slate-100">in your browser</em> before
            they ever leave your device. Then they&apos;re split into
            shards and distributed across three independent cloud
            providers. No single entity — not AWS, not Google, not even
            RESQD — can read or reconstruct your data.
          </p>

          <p>
            But security without proof is just a promise. That&apos;s
            why every access to your vault rotates a cryptographic
            canary and commits the result to the blockchain. You
            don&apos;t have to trust us when we say nobody looked.{" "}
            <span className="text-slate-100 font-semibold">
              You can verify it mathematically.
            </span>
          </p>

          <p>
            This isn&apos;t another cloud storage product. It&apos;s
            the first{" "}
            <span className="text-slate-100 font-semibold">
              digital safety deposit box
            </span>{" "}
            that uses the laws of mathematics to guarantee what physical
            vaults use steel walls to approximate:{" "}
            <em className="text-slate-100">
              your most treasured assets are safe, and you can prove it.
            </em>
          </p>
        </div>

        <div className="mt-16 border-t border-slate-900 pt-12 text-center">
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
