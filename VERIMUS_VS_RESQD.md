# Verimus vs RESQD — Two Branches of the Same Tree

*A comparison of two projects born from the same 2018 patent idea, built independently by two of the original four co-inventors.*

---

## The Shared DNA

Both projects answer the same question from 2018: *how do you prove nobody has touched your files?* Both use blockchain for integrity, encryption for confidentiality, and distributed storage for resilience. But they took radically different paths to get there.

---

## Architecture Philosophy

| | **Verimus** (Eric) | **RESQD** (Kevin) |
|---|---|---|
| **Core thesis** | Build the infrastructure from scratch | Stand on the shoulders of cloud giants |
| **Network model** | Fully decentralized P2P mesh | Centralized API + multi-cloud backends |
| **Blockchain** | Custom chain with 5-stage consensus | Anchor on an existing L2 (Base/Ethereum) |
| **Storage** | Peer nodes store shards across the mesh | S3 + GCS erasure-coded shards |
| **Trust model** | Trustless — no single operator | Zero-knowledge — operator can't read data |

Eric built a **decentralized network** — every peer is a storage node, consensus participant, and validator. Kevin built a **zero-knowledge SaaS** — one operator, but the operator is cryptographically blind.

## Tech Stack

| | **Verimus** | **RESQD** |
|---|---|---|
| **Language** | TypeScript / Node.js | Rust (core + API), TypeScript (frontend) |
| **Frontend** | React + Zustand + Vite | Next.js + Tailwind |
| **Database** | MongoDB (ledger state) | DynamoDB (auth, rings, audit) |
| **Runtime** | Node.js P2P daemon | AWS Lambda (serverless) |
| **Crypto libs** | Node.js crypto (RSA, AES) | WASM (XChaCha20, ML-KEM-768, BLAKE3, Argon2id) |
| **Code size** | ~21K lines across 198 files | ~15K lines across ~80 files |

## Cryptographic Approach

**Verimus:**
- RSA keypairs for node identity
- AES stream encryption for payloads
- Proof-of-Absorption — cryptographic handoff verification ensuring physical disk writes before block minting
- BFT consensus with GlobalAuditor for Byzantine fault detection

**RESQD:**
- WebAuthn passkeys + PRF extension for key derivation (zero passwords)
- XChaCha20-Poly1305 for file encryption
- ML-KEM-768 (post-quantum) key encapsulation
- X25519 ECDH for sharing between users
- Canary chain — every access rotates a hash chain, anchored on-chain, proving exact access count

Eric went deeper on **network-level security** (BFT, proof-of-absorption, Byzantine detection). Kevin went deeper on **cryptographic sophistication** (post-quantum, canary tamper detection, zero-knowledge key derivation).

## Blockchain Usage

**Verimus** built its own blockchain:
- Custom 5-stage consensus: Pending → Eligible → Confirmed → Settled → Committed
- Native VERI token with wallet management and double-spend prevention
- O(1) checkpoint pruning at 1M block intervals
- Fork settlement via BftCoordinator
- The chain IS the product — it's the backbone of the storage network

**RESQD** anchors on an existing chain:
- Base Sepolia L2 (Ethereum ecosystem)
- Smart contract `ResqdCanaryAnchor` — stores commitment hashes
- ~$0.003 per anchor transaction
- The chain is a **witness**, not the backbone — it proves access history without running consensus

Eric built a blockchain. Kevin rented one.

## Storage Model

**Verimus** — storage is the network:
- Peer nodes ARE the storage backends
- 7 pluggable storage providers (local, memory, S3, Glacier, GitHub, SMB, SFTP)
- Stream-based encryption for multi-GB files with near-zero memory footprint
- Proof-of-Absorption ensures shards physically land on disk before commitment

**RESQD** — storage is cloud infrastructure:
- Reed-Solomon 4+2 erasure coding (any 4 of 6 shards reconstruct)
- Client-side WASM encryption before upload (server never sees plaintext)
- Parallel presigned-URL uploads directly to S3
- Multi-cloud target (S3 + GCS, Azure planned)

## What Eric Got Right That Kevin Didn't

1. **True decentralization** — no single operator to trust or compromise
2. **Stream processing** — handles multi-GB files without memory pressure; RESQD loads everything into WASM memory
3. **Storage flexibility** — 7 backend drivers vs RESQD's 2 (S3, GCS)
4. **Token economics** — a real incentive layer for storage providers; RESQD has no incentive model for infrastructure participation
5. **Full test infrastructure** — hermetic in-memory test environment; RESQD relies on deployed AWS resources for integration testing

## What Kevin Got Right That Eric Didn't

1. **Zero ops for users** — no daemon to run, no peers to discover, just a URL
2. **Post-quantum crypto** — ML-KEM-768 future-proofs against quantum attacks
3. **Passkey auth** — no passwords, no seed phrases, just Touch ID
4. **Family sharing model** — rings, roles, estate triggers for digital inheritance
5. **Canary tamper detection** — provable access counting, not just storage integrity
6. **Shipped to production** — live at resqd.ai with real users today

## The Real Difference

Verimus is an **infrastructure project** — it builds the pipes. You'd deploy it to create a storage network.

RESQD is a **consumer product** — it hides the pipes. Your grandma could use it (on a desktop, not iOS... yet).

Eric built the harder thing. Kevin built the more shippable thing. Both are recognizable descendants of the same whiteboard session in 2018.

---

*"Four guys who once believed your secrets should actually stay secret. We still do."*
