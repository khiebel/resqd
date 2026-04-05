import Link from "next/link";

export default function TermsPage() {
  return (
    <main className="min-h-screen bg-black text-slate-100">
      <nav className="sticky top-0 z-20 backdrop-blur bg-black/70 border-b border-slate-900">
        <div className="mx-auto max-w-4xl px-6 py-4 flex items-center justify-between">
          <Link href="/" className="font-bold tracking-tight text-lg">RESQD</Link>
          <div className="flex items-center gap-6 text-sm text-slate-400">
            <Link href="/security-model/" className="hover:text-slate-100">Security</Link>
            <Link href="/privacy/" className="hover:text-slate-100">Privacy</Link>
            <Link href="/terms/" className="text-slate-100">Terms</Link>
            <Link href="/signup/" className="rounded-lg bg-amber-500 text-slate-900 font-semibold px-4 py-2">Sign up</Link>
          </div>
        </div>
      </nav>

      <article className="mx-auto max-w-3xl px-6 py-16">
        <h1 className="text-4xl font-bold mb-4">Terms of Service</h1>
        <p className="text-sm text-slate-500 mb-4">
          Last updated: 2026-04-04 · Alpha version
        </p>
        <div className="bg-amber-500/5 border border-amber-500/30 rounded-lg p-4 mb-10 text-xs text-amber-200">
          <b>Alpha notice:</b> RESQD is in alpha. The service may break,
          data may be lost, and features may change without warning.
          Don&apos;t put anything in it you can&apos;t afford to lose until
          we ship v1.
        </div>

        <div className="space-y-10 text-slate-300 text-sm leading-relaxed [&_h2]:text-xl [&_h2]:font-bold [&_h2]:text-slate-100 [&_h2]:mb-3 [&_b]:text-slate-100 [&_a]:text-amber-400 [&_a:hover]:underline [&_ul]:list-disc [&_ul]:pl-6 [&_ul]:space-y-1.5">

          <section>
            <h2>Who&apos;s agreeing to what</h2>
            <p>
              These terms are between you (&quot;you&quot;) and the
              operator of RESQD (&quot;we&quot;, &quot;us&quot;). By
              creating an account, you agree to them. If you don&apos;t
              agree, don&apos;t create an account.
            </p>
          </section>

          <section>
            <h2>What RESQD is</h2>
            <p>
              RESQD is a zero-knowledge encrypted storage service. Your
              files are encrypted in your browser before upload; we
              store only ciphertext and metadata sufficient to return
              it to you. See the{" "}
              <Link href="/security-model/">Security Model</Link> for
              the technical architecture.
            </p>
          </section>

          <section>
            <h2>Your responsibilities</h2>
            <ul>
              <li>
                <b>Keep your passkey and/or master key safe.</b> They
                are what unlock your vault. If they&apos;re lost, your
                data is unrecoverable. We cannot help — we don&apos;t
                hold a copy.
              </li>
              <li>
                <b>Don&apos;t use RESQD to store illegal content.</b>{" "}
                Specifically: child sexual abuse material, content that
                violates sanctions laws, or anything that infringes a
                third party&apos;s intellectual property.
              </li>
              <li>
                <b>Don&apos;t use RESQD to attack others.</b> No
                malware distribution, no phishing payloads, no command-
                and-control infrastructure.
              </li>
              <li>
                <b>Don&apos;t abuse the infrastructure.</b> Rate limits,
                fair use of storage caps, no automated content scraping
                of other users (there is nothing to scrape — this is
                listed for clarity).
              </li>
              <li>
                <b>Comply with export controls.</b> RESQD uses strong
                cryptography. Some jurisdictions restrict the use,
                import, or export of cryptographic products. You are
                responsible for compliance in your jurisdiction.
              </li>
            </ul>
          </section>

          <section>
            <h2>Our responsibilities</h2>
            <ul>
              <li>
                <b>Run the service with reasonable care.</b> We target
                durability through multi-cloud erasure coding (4-of-6
                shards recoverable) and standard backup practices.
              </li>
              <li>
                <b>Don&apos;t read your data.</b> We can&apos;t, by
                design — see the Security Model — but we also
                contractually agree not to attempt to.
              </li>
              <li>
                <b>Be honest about incidents.</b> Any security incident
                affecting account metadata will be disclosed within 72
                hours of discovery.
              </li>
              <li>
                <b>Give you 30 days&apos; notice</b> before any material
                change to these terms or to the pricing on your current
                plan.
              </li>
            </ul>
          </section>

          <section>
            <h2>Termination</h2>
            <p>
              You can delete your account and all data at any time from{" "}
              <Link href="/settings/">Settings</Link> or by emailing{" "}
              <a href="mailto:privacy@resqd.ai">privacy@resqd.ai</a>.
              We may terminate accounts that violate these terms
              (illegal content, infrastructure abuse) with reasonable
              notice and an opportunity to export data where legally
              permissible.
            </p>
          </section>

          <section>
            <h2>Disclaimer and liability</h2>
            <p>
              Alpha service is provided <b>AS IS, WITHOUT WARRANTIES</b>.
              We do our best, but we make no guarantee of uptime,
              durability, or data recovery during the alpha period.
              To the maximum extent permitted by law, our aggregate
              liability for any claim related to RESQD during the
              alpha is limited to the amount you paid us in the prior
              12 months. For free-tier users, that is zero.
            </p>
            <p>
              These limitations do not apply where they are prohibited
              by law, and do not limit liability for our gross
              negligence, willful misconduct, or violations of
              applicable data protection laws.
            </p>
          </section>

          <section>
            <h2>Intellectual property</h2>
            <p>
              You own your data. You grant us a narrow license to
              store, transmit, and retrieve your encrypted data on your
              behalf — nothing more. We cannot, and do not, use your
              content for any purpose other than returning it to you
              when you ask. The RESQD name, logo, and source code
              (where published) remain our property or that of the
              respective licensors.
            </p>
          </section>

          <section>
            <h2>Governing law</h2>
            <p>
              These terms are governed by the laws of the State of
              Delaware, USA, without regard to conflict of laws
              principles. Disputes will be resolved in state or federal
              courts located in Delaware, except where you have
              mandatory consumer protections in your jurisdiction that
              override this.
            </p>
          </section>

          <section>
            <h2>Contact</h2>
            <p>
              <a href="mailto:legal@resqd.ai">legal@resqd.ai</a>
            </p>
          </section>
        </div>
      </article>
    </main>
  );
}
