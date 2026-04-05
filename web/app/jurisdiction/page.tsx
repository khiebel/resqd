import Link from "next/link";

export const metadata = {
  title: "Jurisdiction & geo restrictions · RESQD",
  description:
    "Where RESQD is and isn't available, why, and how to appeal a geo block.",
};

export default function JurisdictionPage() {
  return (
    <main className="min-h-screen bg-black text-slate-100">
      <nav className="sticky top-0 z-20 backdrop-blur bg-black/70 border-b border-slate-900">
        <div className="mx-auto max-w-4xl px-6 py-4 flex items-center justify-between">
          <Link href="/" className="font-bold tracking-tight text-lg">
            RESQD
          </Link>
          <div className="flex items-center gap-6 text-sm text-slate-400">
            <Link href="/security-model/" className="hover:text-slate-100">
              Security
            </Link>
            <Link href="/privacy/" className="hover:text-slate-100">
              Privacy
            </Link>
            <Link href="/terms/" className="hover:text-slate-100">
              Terms
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
        <h1 className="text-4xl font-bold mb-4">Jurisdiction & geo restrictions</h1>
        <p className="text-sm text-slate-500 mb-8">
          Last updated: 2026-04-05 · Alpha version
        </p>

        <div className="space-y-10 text-slate-300 text-sm leading-relaxed [&_h2]:text-xl [&_h2]:font-bold [&_h2]:text-slate-100 [&_h2]:mb-3 [&_b]:text-slate-100 [&_a]:text-amber-400 [&_a:hover]:underline [&_ul]:list-disc [&_ul]:pl-6 [&_ul]:space-y-1.5 [&_table]:w-full [&_table]:text-xs [&_th]:text-left [&_th]:py-2 [&_th]:pr-4 [&_td]:py-1 [&_td]:pr-4 [&_th]:border-b [&_th]:border-slate-800">
          <section>
            <h2>The short version</h2>
            <p>
              RESQD is operated from the United States and must comply with
              US sanctions and export-control regulations. We make a{" "}
              <b>best-effort attempt</b> to block access from jurisdictions
              where providing a strong-crypto privacy service to the general
              public is illegal, sanctioned, or carries meaningful legal
              risk for the operator.
            </p>
            <p>
              This is not a technical border. A VPN defeats it in one click.
              It is a good-faith compliance posture, documented publicly so
              our intent is unambiguous.
            </p>
          </section>

          <section>
            <h2>Who is currently restricted</h2>
            <p>
              The live block list is configured via an environment variable
              on our API and can be updated at any time. As of the last
              update of this page, it includes:
            </p>
            <table>
              <thead>
                <tr>
                  <th>Country</th>
                  <th>Primary reason</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>Cuba</td>
                  <td>US OFAC comprehensive sanctions</td>
                </tr>
                <tr>
                  <td>Iran</td>
                  <td>US OFAC comprehensive sanctions</td>
                </tr>
                <tr>
                  <td>North Korea</td>
                  <td>US OFAC comprehensive sanctions</td>
                </tr>
                <tr>
                  <td>Syria</td>
                  <td>US OFAC comprehensive sanctions</td>
                </tr>
                <tr>
                  <td>Russia</td>
                  <td>US sanctions program (post-2022)</td>
                </tr>
                <tr>
                  <td>Belarus</td>
                  <td>US sanctions program</td>
                </tr>
                <tr>
                  <td>China (mainland)</td>
                  <td>Strong-crypto export and local-law risk</td>
                </tr>
              </tbody>
            </table>
            <p className="mt-3">
              Hong Kong, Macau, and Taiwan are treated as distinct
              jurisdictions and are <b>not</b> on the block list.
            </p>
          </section>

          <section>
            <h2>What you see when you&apos;re blocked</h2>
            <p>
              A request from a blocked country returns HTTP{" "}
              <code className="text-slate-400">451 Unavailable For Legal Reasons</code>{" "}
              and the browser lands here. Our response only echoes your own
              detected country code back to you — we don&apos;t publish the
              full live block list through the API, so you can&apos;t
              probe it for edge-case additions.
            </p>
          </section>

          <section>
            <h2>If you believe this is wrong</h2>
            <p>
              Email <a href="mailto:support@resqd.ai">support@resqd.ai</a>.
              The operator reviews every appeal individually, in writing,
              and will add case-specific exceptions for users who can
              establish a legitimate claim — for example, a US citizen
              travelling, someone using a VPN endpoint they don&apos;t
              control, or an explicit professional carve-out.
            </p>
            <p className="p-3 bg-amber-500/5 border border-amber-500/20 rounded-lg text-amber-200">
              <b>If appealing is unsafe for you</b> — for example, if the
              local government would retaliate against you for seeking a
              US-based privacy service — please don&apos;t send an
              identifying email. RESQD&apos;s threat model takes your
              safety more seriously than our compliance posture. The
              source code is{" "}
              <a href="https://github.com/khiebel/resqd">public</a>; run
              your own instance against your own cloud storage, which
              removes this layer entirely.
            </p>
          </section>

          <section>
            <h2>Trust boundary disclosure</h2>
            <p>
              RESQD is unilaterally deciding to restrict some users in
              advance of any sanction being imposed directly on them. We
              list this here as a known trust boundary alongside the
              others on our{" "}
              <Link href="/security-model/">Security Model page</Link>.
              If this posture is a non-starter, the source code is
              available under AGPL-3.0 — you can run a private instance
              against your own S3/GCS/Azure buckets and none of the
              above applies.
            </p>
          </section>

          <section>
            <h2>What we log</h2>
            <p>
              When a request is geo-blocked, our Lambda emits a single
              warning line containing the detected country code and the
              path. We do not log IP addresses, user agents, or any
              other headers beyond the country code. The decision is
              stateless per request — a user who visits from a blocked
              country, gets a 451, and then comes back from a
              non-blocked region on a subsequent request is
              indistinguishable from any other first-time visitor.
            </p>
          </section>
        </div>

        <div className="mt-12 text-xs text-slate-500">
          The authoritative, developer-level version of this document
          lives in{" "}
          <a href="https://github.com/khiebel/resqd/blob/main/docs/JURISDICTION.md">
            docs/JURISDICTION.md
          </a>{" "}
          in the RESQD repo, including the runbook for updating the
          block list and the Cloudflare edge rule configuration.
        </div>
      </article>
    </main>
  );
}
