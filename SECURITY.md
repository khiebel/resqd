# Security policy

RESQD is a cryptographic product. Bugs in it can silently undermine
the confidentiality, integrity, and availability guarantees we make.
We take that seriously.

## Reporting a vulnerability

**Please do not open a public GitHub issue for security reports.**

Instead, email `security@resqd.ai` with:

- A description of the issue
- Steps to reproduce (or a proof-of-concept)
- Your assessment of the impact
- Whether you'd like credit, and how you'd like to be attributed

You will get an acknowledgment within 72 hours. If you don't,
something has gone wrong on our end — please escalate by also emailing
`khiebel+resqd-security@gmail.com`.

## Scope

In-scope:

- The Rust crypto core in [`core/`](./core/) and its WASM bindings
  (this is what runs in your browser and what the recover CLI uses)
- The API in [`api/`](./api/) — auth, session handling, sharing
  endpoints, geo-restriction middleware, quota enforcement
- The WebAuthn + PRF key-derivation flow in
  [`web/app/lib/passkey.ts`](./web/app/lib/passkey.ts)
- The share wrap key derivation in
  [`core/src/crypto/share.rs`](./core/src/crypto/share.rs)
- The Recovery Kit format and the offline reader in
  [`recover/`](./recover/) — see
  [`docs/RECOVERY_KIT_SPEC.md`](./docs/RECOVERY_KIT_SPEC.md)
- The Solidity canary anchor contract in [`contracts/`](./contracts/)
- The MCP server in [`mcp/`](./mcp/) when invoked locally with a
  legitimate user token + master key

Out of scope (for now):

- Denial-of-service against the live `api.resqd.ai` origin. We rate
  limit at Cloudflare; the Lambda does not promise DoS resistance.
- Self-XSS in the settings page (requires physical or console access
  to the victim's browser).
- Known limitations already documented in the spec — e.g. unsharing
  does not retroactively revoke already-fetched data (this is
  inherent to symmetric-key cryptography, called out in the share
  flow comments and the `/security-model` page).
- Third-party dependencies for which a fix would require upstream
  patches — please also report those upstream.

## Known non-issues

- **"The Recovery Kit contains the master key in plaintext."** Yes.
  This is deliberate and documented in
  [`docs/RECOVERY_KIT_SPEC.md`](./docs/RECOVERY_KIT_SPEC.md) — the kit
  IS the last-resort artifact, demanding a second factor to unlock it
  would defeat its purpose. Users are responsible for storing the kit
  like a printed passphrase. A BIP-39 mnemonic wrap is planned as an
  opt-in.
- **"I can `curl api.resqd.ai` with a fake `cf-ipcountry` header and
  bypass the geo block."** Correct, because Cloudflare overwrites the
  header at the edge based on your actual IP before it reaches the
  origin. The Lambda middleware is a defence-in-depth fallback for
  the "CF rule misconfigured" failure mode, not the primary
  enforcement layer. The primary layer is the Cloudflare WAF rule in
  front of the Lambda.
- **"The canary anchor is on Base Sepolia, not mainnet."** Yes — the
  alpha anchors to Sepolia testnet for cost reasons. A production
  deployment would anchor to Base mainnet or another L2. The contract
  itself is unchanged.

## Disclosure timeline

- **Day 0:** You report via `security@resqd.ai`.
- **Day 1-3:** Acknowledgment.
- **Day 4-14:** Triage + fix development.
- **Day 14-90:** Coordinated disclosure — we ship a fix, you publish,
  we credit you (if you'd like).
- **Day 90+:** If we haven't shipped a fix, you are free to publish
  regardless. We will not threaten legal action against good-faith
  researchers.

## PGP

Not currently offered. If you need end-to-end encrypted reporting,
open a GitHub issue asking for a PGP channel and one will be
provisioned.

## Bug bounty

RESQD is an open-source alpha run by an individual. There is no
formal bug bounty program. For significant vulnerabilities that
materially change the security posture of the product, the operator
is willing to send a meaningful thank-you — contact via email.
