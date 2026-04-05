import Link from "next/link";

export default function PrivacyPage() {
  return (
    <main className="min-h-screen bg-black text-slate-100">
      <nav className="sticky top-0 z-20 backdrop-blur bg-black/70 border-b border-slate-900">
        <div className="mx-auto max-w-4xl px-6 py-4 flex items-center justify-between">
          <Link href="/" className="font-bold tracking-tight text-lg">RESQD</Link>
          <div className="flex items-center gap-6 text-sm text-slate-400">
            <Link href="/security-model/" className="hover:text-slate-100">Security</Link>
            <Link href="/privacy/" className="text-slate-100">Privacy</Link>
            <Link href="/terms/" className="hover:text-slate-100">Terms</Link>
            <Link href="/signup/" className="rounded-lg bg-amber-500 text-slate-900 font-semibold px-4 py-2">Sign up</Link>
          </div>
        </div>
      </nav>

      <article className="mx-auto max-w-3xl px-6 py-16">
        <h1 className="text-4xl font-bold mb-4">Privacy Policy</h1>
        <p className="text-sm text-slate-500 mb-12">
          Last updated: 2026-04-04 · Alpha version
        </p>

        <div className="space-y-10 text-slate-300 text-sm leading-relaxed [&_h2]:text-xl [&_h2]:font-bold [&_h2]:text-slate-100 [&_h2]:mb-3 [&_ul]:list-disc [&_ul]:pl-6 [&_ul]:space-y-1.5 [&_b]:text-slate-100 [&_a]:text-amber-400 [&_a:hover]:underline">

          <section>
            <h2>The short version</h2>
            <p>
              RESQD is a zero-knowledge vault. The entire product is
              designed around a single premise: <b>we can't read what
              you store, so we can't sell, share, or lose it in a
              breach</b>. This policy exists to put specifics behind
              that claim and to cover the small amount of information
              we <i>do</i> collect so the product can function.
            </p>
            <p>
              Read the{" "}
              <Link href="/security-model/">Security Model</Link> for
              the cryptographic details of how zero-knowledge is
              enforced.
            </p>
          </section>

          <section>
            <h2>What we collect</h2>
            <ul>
              <li>
                <b>Email address.</b> Used for login, password-free
                account recovery, and rare product emails (billing
                receipts, security notices). Not used for marketing
                spam.
              </li>
              <li>
                <b>Passkey public key.</b> A WebAuthn credential created
                on your device and synced to your platform keychain.
                RESQD stores only the public half. The private half
                never leaves your authenticator.
              </li>
              <li>
                <b>Encrypted vault data.</b> Ciphertext shards, wrapped
                per-asset keys, and encrypted metadata blobs. We cannot
                decrypt any of this.
              </li>
              <li>
                <b>Request metadata.</b> Timestamps, IP addresses
                (briefly, for rate limiting and abuse detection),
                request sizes, HTTP methods. Standard server logs.
                Retained ≤ 30 days.
              </li>
              <li>
                <b>Canary commitments.</b> 32-byte cryptographic
                fingerprints of your vault access history, written to
                a public blockchain. These are opaque — nothing in them
                identifies you or your data to an outside observer.
              </li>
              <li>
                <b>Billing information</b> <i>(future)</i>. When we
                turn on payments, card details are handled by Stripe;
                RESQD never sees card numbers. We store the subscription
                status and last-4 digits for support.
              </li>
            </ul>
          </section>

          <section>
            <h2>What we do NOT collect</h2>
            <ul>
              <li><b>Plaintext of your files.</b> Physically impossible — it's encrypted in your browser before we see it.</li>
              <li><b>Plaintext filenames.</b> Same — filenames are encrypted in a separate metadata blob.</li>
              <li><b>Your master key.</b> It's derived from your passkey via the WebAuthn PRF extension and never transmitted.</li>
              <li><b>Third-party analytics cookies, trackers, or ad-tech.</b> This site uses zero third-party scripts.</li>
              <li><b>Device fingerprints, telemetry, or behavioral profiling.</b></li>
              <li><b>Social contacts, address books, or other identity graph data.</b></li>
            </ul>
          </section>

          <section>
            <h2>Who we share with</h2>
            <ul>
              <li>
                <b>Cloud storage providers (AWS, Google Cloud, Azure):</b>{" "}
                they hold your encrypted shards. They see ciphertext
                bytes and your asset IDs; nothing else. No single
                provider has a complete copy of any file.
              </li>
              <li>
                <b>Base L2 blockchain:</b> canary commitments and asset
                ID hashes are written publicly. Anyone can read them.
                They are opaque hashes — you cannot derive a filename
                or a user from them.
              </li>
              <li>
                <b>Stripe</b> <i>(future)</i>: payment processing only.
              </li>
              <li>
                <b>Lawful court orders:</b> if compelled by a valid
                court order in a jurisdiction we operate in, we will
                hand over what we have. What we have is encrypted data
                and account metadata. We cannot produce plaintext.
              </li>
            </ul>
            <p>
              <b>We do not sell your data. Ever. Not even "anonymized"
              or "aggregated" versions.</b> The whole architecture
              prevents this.
            </p>
          </section>

          <section>
            <h2>How long we keep it</h2>
            <ul>
              <li>Encrypted vault data: as long as your account is active, plus 30 days grace after cancellation.</li>
              <li>Account metadata: as long as your account is active.</li>
              <li>Request logs: ≤ 30 days.</li>
              <li>Backups: standard cloud provider backups with encryption retained per cloud provider defaults.</li>
              <li>Blockchain anchors: forever (append-only by design — we cannot delete them).</li>
            </ul>
          </section>

          <section>
            <h2>Your rights</h2>
            <p>
              You can delete any asset at any time from the vault page.
              You can delete your account and all associated data by
              emailing{" "}
              <a href="mailto:privacy@resqd.ai">privacy@resqd.ai</a>.
              On account deletion we purge your user row, all wrapped
              keys, and all encrypted shards within 30 days. The
              on-chain canary history for your past assets remains
              forever — it's cryptographically opaque so it cannot be
              used to identify you, but we cannot delete it.
            </p>
            <p>
              If you are in the EU, UK, or California, you additionally
              have GDPR/CCPA rights of access, correction, portability,
              and erasure. Contact{" "}
              <a href="mailto:privacy@resqd.ai">privacy@resqd.ai</a>{" "}
              and we'll process requests within 30 days.
            </p>
          </section>

          <section>
            <h2>Children</h2>
            <p>
              RESQD is not directed at children under 13. We do not
              knowingly collect data from children under 13. If you
              believe a child under 13 has registered, email{" "}
              <a href="mailto:privacy@resqd.ai">privacy@resqd.ai</a>{" "}
              and we will remove the account.
            </p>
          </section>

          <section>
            <h2>Changes</h2>
            <p>
              Material changes to this policy will be announced via the
              email on your account with at least 30 days notice before
              taking effect.
            </p>
          </section>

          <section>
            <h2>Contact</h2>
            <p>
              <a href="mailto:privacy@resqd.ai">privacy@resqd.ai</a>
            </p>
          </section>
        </div>
      </article>
    </main>
  );
}
