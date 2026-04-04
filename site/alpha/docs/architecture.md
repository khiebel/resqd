# RESQD: Quantum-Secured Digital Vault — Implementation Plan
## Brand: resqd.ai (registered 2026-04-03, Cloudflare)

## Context

Kevin holds patent US11431691B2 (blockchain-based secure storage, assigned to employer, expires 2041). The vision: build the world's first consumer product that combines post-quantum cryptography, blockchain integrity verification, multi-cloud erasure-coded storage, and cryptographic tamper detection into a simple family/business digital vault.

**Market gap is massive:** No consumer product exists that combines these capabilities. Competitors (Gentreo, Prisidio, Cipherwill) are fragmented across estate planning, photo vaults, or dead man's switches — all using traditional AES-256, none quantum-resistant, none multi-cloud distributed, none blockchain-verified.

**Patent navigation: DESIGN AROUND (confirmed).** We use entirely different algorithms (BLAKE3 vs SHA-256, XChaCha20-Poly1305 vs AES-256-CBC, ML-KEM-768 vs RSA, Merkle DAG vs linear chain) that achieve similar goals through different methods. IP counsel review recommended before commercial launch.

**Build order: Rust crypto core first (confirmed).** Foundation that everything else depends on.

---

## Architecture Summary

### Stack
- **Core engine:** Rust (crypto performance, WASM compilation, memory safety)
- **API:** AWS API Gateway + Lambda (Rust `provided.al2023` runtime)
- **Web:** Next.js 15 on Cloudflare Pages (cost-effective, familiar stack)
- **Mobile:** React Native (shared TS types with web, Rust core via UniFFI)
- **Storage:** AWS S3 + GCP GCS + Azure Blob (Reed-Solomon 4,2 erasure coding)
- **Blockchain:** Base L2 (low fees ~$0.002/tx, OP Stack, EVM compatible)
- **Key management:** AWS KMS (ML-KEM post-quantum TLS), client-side Argon2id derivation
- **Quantum entropy:** AWS Braket (Rigetti QPU) for key material generation

### Core Crypto (All Patent-Distinct)
| Function | Algorithm | Patent Used | Why Different |
|----------|-----------|-------------|---------------|
| Hashing | BLAKE3 | SHA-256 | Different algorithm, Merkle tree structure |
| Encryption | XChaCha20-Poly1305 | AES-256-CBC | Stream cipher vs block cipher, AEAD vs unauthenticated |
| Key encapsulation | ML-KEM-768 | RSA | Lattice-based vs integer factorization |
| Signatures | ML-DSA-65 | N/A | Post-quantum, not in patent |
| Chaining | Merkle DAG + on-chain roots | Custom linear chain | DAG vs linear, public blockchain vs private |

### Quantum-Hardened Tamper Detection (Core Differentiator)

Real QKD requires quantum hardware and isn't viable for consumer SaaS. Instead, we build 4-layer cryptographic tamper evidence:

1. **Post-quantum encryption** (ML-KEM-768) — resistant to future quantum attacks
2. **Canary token system** — every access rotates cryptographic canaries committed to blockchain. Owner verifies chain length = exact access count. No silent observation possible.
3. **VDF proofs** — each access computes a Verifiable Delay Function (minimum wall-clock time). Prevents backdating access events.
4. **Threshold witnesses** — canary rotation requires (t,n) threshold signatures from multiple independent parties. No single entity can access silently.

### Multi-Key Access (Shamir Secret Sharing)
- Owner: root key
- Adult: 1 share, needs 2-of-3 with another Adult or Owner
- Child: 1 share, needs 3-of-4 (cannot access alone)
- Executor: time-locked share via dead man's switch
- Business Partner: configurable threshold

---

## Cost Estimate

| Phase | Monthly Cost |
|-------|-------------|
| Development (free tiers) | ~$2-5 |
| MVP with 100 users | ~$95-145 |
| 10,000 users | ~$6,500-11,000 |

Revenue at 10K users ($10-20/mo): $100K-200K/mo. Viable unit economics.

---

## MVP Scope (3 Months)

**Goal:** Fully functional web app where a customer can securely vault digital assets with quantum-hardened tamper detection.

**Includes:**
- Upload files (photos, docs, PDFs, crypto keys) up to 100MB
- Client-side encryption via Rust WASM (browser never sends plaintext)
- BLAKE3 hashing + XChaCha20-Poly1305 encryption
- Reed-Solomon erasure coding across AWS S3 + GCP GCS
- On-chain hash + canary commitments (Base L2)
- Canary-based tamper detection with blockchain verification
- Dashboard: "N assets, K accesses, last verified at T"
- Auth: email + WebAuthn passkeys
- Beautiful, simple UX (the product IS simplicity over complexity)

**Not in MVP:** Mobile app, key rings/sharing, dead man's switch, VDFs, ZK proofs, Braket quantum entropy

---

## Build Sequence

**Weeks 1-2:** Rust core crypto module — BLAKE3, XChaCha20-Poly1305, ML-KEM-768, canary tokens. Unit tests.
**Weeks 3-4:** Reed-Solomon erasure coding. WASM compilation. S3 + GCS upload/download with shard distribution.
**Weeks 5-6:** Canary token system. Base L2 Solidity contract. On-chain commitment flow.
**Weeks 7-8:** Next.js frontend. File upload UX. Client-side WASM encryption. Auth (passkeys).
**Weeks 9-10:** Integration testing. Canary verification dashboard. Asset retrieval flow.
**Weeks 11-12:** Polish, security review, deploy to production.

---

## Brand

**RESQD** — resqd.ai (registered 2026-04-03)
- Tagline: *"Your digital assets, rescued."*
- Positioning: The world's first quantum-secured digital vault. Multi-cloud. Blockchain-verified. Tamper-proven.
- resqd.com available on HugeDomains for $16,495 (acquire later if product takes off)

---

## Documentation Structure

All architecture, design docs, and marketing materials live in:
`/Users/khiebel/CodeBucket/resqd/docs/`

```
resqd/
├── docs/
│   ├── architecture/
│   │   ├── overview.md          — system architecture
│   │   ├── crypto.md            — cryptographic design decisions
│   │   ├── canary-system.md     — tamper detection design
│   │   ├── multi-cloud.md       — erasure coding + shard distribution
│   │   ├── blockchain.md        — on-chain commitments design
│   │   ├── key-management.md    — KMS, Shamir, key rings
│   │   └── patent-navigation.md — how we avoid patent claims
│   ├── marketing/
│   │   ├── positioning.md       — brand positioning + messaging
│   │   ├── competitor-analysis.md
│   │   └── one-pager.md         — investor/customer one-pager
│   └── adr/                     — Architecture Decision Records
│       ├── 001-rust-core.md
│       ├── 002-blake3-over-sha256.md
│       ├── 003-base-l2-blockchain.md
│       └── ...
├── core/                        — Rust crypto engine
│   ├── Cargo.toml
│   └── src/
│       ├── crypto/              — ML-KEM, BLAKE3, XChaCha20
│       ├── erasure/             — Reed-Solomon
│       ├── canary/              — canary token system
│       └── lib.rs
├── contracts/                   — Solidity smart contracts
│   └── src/Resqd.sol
├── web/                         — Next.js frontend
│   └── ...
└── infra/                       — Terraform/CDK for AWS
    └── ...
```

---

## Verification

- Rust core: `cargo test` with NIST test vectors for ML-KEM-768, BLAKE3
- Erasure coding: round-trip encode/decode with simulated shard loss
- Canary system: simulate access, verify blockchain commitment chain
- End-to-end: upload file via web → verify shards in S3+GCS → verify on-chain hash → retrieve and decrypt → verify canary rotation
- Security: no plaintext keys ever leave the browser (verify via network inspector)
