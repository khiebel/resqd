import Link from "next/link";

export default function AboutPage() {
  return (
    <main className="mx-auto max-w-2xl px-6 py-20 text-slate-100">
      <Link
        href="/"
        className="text-xs text-slate-500 hover:text-slate-300 mb-12 block"
      >
        &larr; resqd.ai
      </Link>

      <h1 className="text-3xl font-bold mb-8">About</h1>

      <div className="space-y-6 text-sm text-slate-400 leading-relaxed">
        <p>
          Some ideas refuse to stay buried.
        </p>

        <p>
          In 2018, four friends sat around a whiteboard and asked a question
          that wouldn&rsquo;t leave them alone: <em>what if you could prove,
          cryptographically, that nobody had ever looked at your most
          important files?</em> Not just encrypt them &mdash; prove they
          were untouched. They wrote a patent. Life moved on. The idea
          didn&rsquo;t.
        </p>

        <p>
          Years later, the math caught up. Post-quantum cryptography
          matured. Blockchain anchoring became cheap. Erasure coding got
          fast enough to run in a browser tab. The pieces that were
          missing in 2018 were suddenly sitting on the shelf, waiting to
          be assembled.
        </p>

        <p>
          So we assembled them.
        </p>

        <p>
          RESQD is a nostalgic tool, brought back to life for old
          times&rsquo; sake &mdash; for Eric, Jake, Dave, and Kevin. Four
          guys who once believed your secrets should actually stay secret.
          We still do.
        </p>

        <p className="text-slate-600 text-xs pt-8">
          Built with Rust, WebAssembly, and stubbornness.
        </p>
      </div>
    </main>
  );
}
