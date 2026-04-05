import Link from "next/link";

/**
 * Security model page — the honest technical explanation of RESQD's
 * zero-knowledge claim. Not marketing copy. Specific primitives,
 * specific trust boundaries, specific failure modes. This page is
 * what a security-literate user reads before deciding whether the
 * product's promises are worth believing.
 */
export default function SecurityModelPage() {
  return (
    <main className="min-h-screen bg-black text-slate-100">
      <nav className="sticky top-0 z-20 backdrop-blur bg-black/70 border-b border-slate-900">
        <div className="mx-auto max-w-4xl px-6 py-4 flex items-center justify-between">
          <Link href="/" className="font-bold tracking-tight text-lg">
            RESQD
          </Link>
          <div className="flex items-center gap-6 text-sm text-slate-400">
            <Link href="/security-model/" className="text-slate-100">Security</Link>
            <Link href="/privacy/" className="hover:text-slate-100">Privacy</Link>
            <Link href="/terms/" className="hover:text-slate-100">Terms</Link>
            <Link href="/signup/" className="rounded-lg bg-amber-500 text-slate-900 font-semibold px-4 py-2">
              Sign up
            </Link>
          </div>
        </div>
      </nav>

      <article className="mx-auto max-w-3xl px-6 py-16 prose-styled">
        <h1 className="text-4xl font-bold mb-4">Security Model</h1>
        <p className="text-sm text-slate-500 mb-12">
          Last updated: 2026-04-04 · Alpha version
        </p>

        <Section title="The one-line claim">
          <p>
            RESQD servers cannot read the contents of your vault, cannot
            read the filenames of the things you store, and cannot
            access your vault without leaving a cryptographic fingerprint
            on a public blockchain.
          </p>
          <p>
            Everything below is what makes that claim honest — and
            specifically which threats it does and does not address.
          </p>
        </Section>

        <Section title="Trust boundaries">
          <p>
            The browser running this app is the trust boundary. Every
            key operation happens inside it, before any data crosses
            the network.
          </p>
          <ul>
            <li>
              <b>Inside the browser:</b> plaintext of your files, the
              master key derived from your passkey, per-asset encryption
              keys, filenames, and metadata.
            </li>
            <li>
              <b>Leaves the browser:</b> encrypted shards (6 per file,
              4-of-6 recoverable), a per-asset key wrapped under your
              master key, an encrypted metadata blob, and your opaque
              asset IDs.
            </li>
            <li>
              <b>RESQD servers (AWS Lambda, S3, DynamoDB) see:</b>{" "}
              ciphertext, wrapped keys, encrypted metadata, your email
              address (only for account recovery), your passkey public
              key, and the number and timing of your API calls.
            </li>
            <li>
              <b>Base L2 blockchain sees:</b> BLAKE3 hashes of your
              asset IDs and 32-byte canary commitments. No filenames,
              no content, no user identifiers.
            </li>
          </ul>
        </Section>

        <Section title="Cryptographic primitives">
          <ul className="space-y-2">
            <li><b>Content encryption:</b> XChaCha20-Poly1305 AEAD, 256-bit keys, 192-bit random nonces.</li>
            <li><b>Hashing:</b> BLAKE3 (commitments, asset ID derivation).</li>
            <li><b>Key encapsulation:</b> ML-KEM-768 (NIST-standardized post-quantum KEM) for future key-agreement operations.</li>
            <li><b>Key derivation from passkey:</b> WebAuthn PRF extension — your authenticator computes a per-credential secret from a fixed salt. The output becomes your master key. The master key never leaves the browser.</li>
            <li><b>Key derivation from passphrase</b> (fallback, not currently exposed): Argon2id with memory ≥ 64 MiB.</li>
            <li><b>Erasure coding:</b> Reed-Solomon 4+2. Any 4 of 6 shards reconstruct the original.</li>
            <li><b>Session tokens:</b> HS256 JWT in HttpOnly cookies; server-held secret never exposed.</li>
            <li><b>Blockchain anchor:</b> Base L2 (Ethereum EVM L2). Gas per anchor: ~38k. Cost: ~$0.0027.</li>
          </ul>
        </Section>

        <Section title="Zero-knowledge architecture in detail">
          <p>
            When you upload a file, these steps happen in order,{" "}
            <b>all inside your browser</b>:
          </p>
          <ol>
            <li>A 32-byte per-asset key is generated with cryptographically secure randomness.</li>
            <li>Your filename and MIME type are wrapped in a header and prepended to the raw file bytes as a frame.</li>
            <li>The framed bytes are encrypted under the per-asset key with XChaCha20-Poly1305.</li>
            <li>The per-asset key is <i>separately</i> encrypted under your master key.</li>
            <li>Your filename + MIME (only) is <i>also</i> separately encrypted under your master key, for display in the vault list without having to decrypt the whole file.</li>
            <li>The ciphertext is Reed-Solomon coded into 6 shards.</li>
            <li>Six presigned upload URLs are requested from the RESQD API.</li>
            <li>Each shard is PUT directly to its storage backend, bypassing the API.</li>
            <li>The API is told to commit the upload, receiving the wrapped per-asset key and the encrypted filename blob as opaque base64 strings.</li>
            <li>The API creates an initial canary commitment and anchors it on Base L2.</li>
          </ol>
          <p>
            Nowhere in this flow does the RESQD API see a plaintext key,
            a plaintext filename, or plaintext content. You can verify
            this yourself by reading the source at{" "}
            <a href="/">github.com/khiebel/resqd</a> (to be published) or
            by inspecting the browser network tab during an upload.
          </p>
        </Section>

        <Section title="Canary tamper detection">
          <p>
            Every read from your vault rotates a cryptographic canary
            chain and writes the new commitment to Base L2.
          </p>
          <ul>
            <li>If RESQD reads your vault without your knowledge, the on-chain sequence number advances past what you expect.</li>
            <li>You can query the contract directly (no RESQD server involvement) to verify the access count.</li>
            <li>Because Base L2 is append-only, RESQD cannot rewrite history to hide an access.</li>
            <li>The canary chain is signed with a per-asset chain, so a malicious administrator cannot replay or forge canaries.</li>
          </ul>
          <p>
            This is the core tamper-evidence guarantee. It converts
            "trust us that we don't look at your data" into a
            cryptographically verifiable claim.
          </p>
        </Section>

        <Section title="What this does NOT protect against">
          <p>Honest about the limits:</p>
          <ul>
            <li>
              <b>Malicious browser extensions:</b> Any extension with
              access to the RESQD tab can read your plaintext before
              encryption. Use a clean profile for sensitive uploads.
            </li>
            <li>
              <b>Compromised endpoint:</b> If your Mac or phone is
              compromised, the attacker has the same view as you. RESQD
              protects data at rest and in transit to the cloud — not
              against a keylogger on your own device.
            </li>
            <li>
              <b>Lost passkey with no backup:</b> If your only passkey
              is lost and the credential is not synced to iCloud
              Keychain / Google Password Manager, you cannot recover
              your vault. We can see your encrypted data but we cannot
              decrypt it. This is by design.
            </li>
            <li>
              <b>Quantum-capable adversary with stored ciphertext
              from 2026:</b> XChaCha20-Poly1305 is believed quantum-
              resistant against key-search attacks (Grover's algorithm
              halves effective key length to ~128 bits, which is still
              secure). The only currently-used primitive at risk from
              sufficiently large quantum computers is the WebAuthn
              credential's elliptic-curve signature, and passkey
              providers are already migrating to PQ signature schemes.
              We will migrate as well when support lands.
            </li>
            <li>
              <b>Traffic analysis:</b> RESQD servers see the number,
              timing, and size of your requests. A well-resourced
              observer could learn rough usage patterns even without
              reading contents. If this matters to you, route traffic
              through Tor or a VPN.
            </li>
            <li>
              <b>Legal compulsion:</b> We will comply with lawful court
              orders targeting data we hold. Since we hold only
              ciphertext and wrapped keys, that compliance is bounded:
              we can hand over the encrypted blobs, but we cannot hand
              over your plaintext because we do not have it.
            </li>
          </ul>
        </Section>

        <Section title="Jurisdiction and geo restrictions">
          <p>
            RESQD is operated from the United States and makes a
            best-effort attempt to block access from jurisdictions
            where providing a strong-crypto privacy service to the
            general public is illegal, sanctioned, or carries
            meaningful legal risk. This is a known, unilateral trust
            boundary — we list it here alongside the others.
          </p>
          <p>
            Full block list, enforcement layers, logging policy, and
            the appeal path are documented at{" "}
            <a href="/jurisdiction/" className="text-amber-400">
              /jurisdiction/
            </a>
            .
          </p>
        </Section>

        <Section title="Open source and verifiability">
          <p>
            The Rust crypto core that runs in your browser as WebAssembly
            is licensed AGPL-3.0 and will be published publicly. You can
            compile the WASM yourself from source, diff it against what
            this site serves, and run the integration tests. The exact
            binary you trust is the binary you can audit.
          </p>
          <p>
            The Solidity contract that anchors canary commitments is
            deployed at{" "}
            <code className="text-amber-300">0xd45453477aa729C157E4840e81F81D4437Ec99f3</code>{" "}
            on Base Sepolia (currently) and is verifiable on Basescan.
          </p>
        </Section>

        <p className="text-sm text-slate-500 mt-16">
          Questions, bug reports, or responsible disclosure:{" "}
          <a href="mailto:security@resqd.ai" className="text-amber-400">
            security@resqd.ai
          </a>
        </p>
      </article>
    </main>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="mb-12">
      <h2 className="text-2xl font-bold mb-4 text-slate-100">{title}</h2>
      <div className="space-y-4 text-slate-300 text-sm leading-relaxed [&_ul]:list-disc [&_ul]:pl-6 [&_ul]:space-y-1.5 [&_ol]:list-decimal [&_ol]:pl-6 [&_ol]:space-y-1.5 [&_b]:text-slate-100 [&_code]:text-xs [&_code]:font-mono [&_code]:bg-slate-900 [&_code]:px-1.5 [&_code]:py-0.5 [&_code]:rounded [&_a]:text-amber-400 [&_a:hover]:underline">
        {children}
      </div>
    </section>
  );
}
