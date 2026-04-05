import Link from "next/link";

export default function Home() {
  return (
    <main className="min-h-screen bg-black text-slate-100 flex items-center justify-center px-6">
      <div className="max-w-xl">
        <h1 className="text-4xl font-bold mb-3">RESQD Alpha</h1>
        <p className="text-slate-400 mb-8">
          Quantum-hardened digital vault. Files are encrypted client-side
          before upload, sharded across multi-cloud storage, and every
          access is anchored on Base L2 as a tamper-evident canary commitment.
        </p>
        <div className="flex gap-3">
          <Link
            href="/upload"
            className="rounded-lg bg-amber-500 text-slate-900 font-medium px-6 py-3"
          >
            Upload a file
          </Link>
          <Link
            href="/fetch"
            className="rounded-lg border border-slate-700 px-6 py-3"
          >
            Fetch a file
          </Link>
        </div>
      </div>
    </main>
  );
}
