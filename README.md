# RESQD

**Zero-knowledge, post-quantum-ready digital vault with on-chain canary anchoring,
read-only sharing, and data-of-last-resort recovery.**

Live at [resqd.ai](https://resqd.ai) (invite-only alpha).

---

## What it is

RESQD is a digital vault where your files are encrypted in your browser
before they leave it, sharded across multiple storage backends via
Reed-Solomon erasure coding, and accompanied by a tamper-evident
access log anchored on a public blockchain. The operator (me) cannot
read your files. Not "will not" — *cannot*: the server has never seen
the keys.

The twist that makes it different from every other "encrypted cloud
storage" claim on the internet: **even if RESQD itself disappears
tomorrow, you can still get your data back**. Every paying user can
download a self-contained Recovery Kit and reconstruct their vault
offline using the open-source [`resqd-recover`](./recover) CLI — with
zero dependency on our servers, our DNS, our cloud accounts, or our
continued existence as a company.

## The crypto stack

| Layer | Algorithm | Crate |
|---|---|---|
| Hash | BLAKE3 | `blake3` |
| AEAD | XChaCha20-Poly1305 | `chacha20poly1305` |
| KEM (post-quantum) | ML-KEM-768 | `ml-kem` |
| ECDH for sharing | X25519 | `x25519-dalek` |
| Key derivation (share wrap) | HKDF-SHA256 | `hkdf` |
| Key derivation (passphrase) | Argon2id | `argon2` |
| Erasure coding | Reed-Solomon 4+2 (GF(256)) | `reed-solomon-erasure` |
| Auth | Passkeys (WebAuthn + PRF extension) | `webauthn-rs` |
| Canary anchor | Base L2 (Ethereum-compatible) | `alloy` |

Master keys are derived in the browser from the passkey's PRF output —
the server never sees any key material.

## Repo layout

```
core/        resqd-core        — crypto primitives (BLAKE3, XChaCha20,
                                 ML-KEM, X25519, Reed-Solomon), WASM bindings
api/         resqd-api         — axum HTTP API, Lambda + local binaries,
                                 DynamoDB passkey auth, sharing endpoints
web/         web               — Next.js 16 static frontend, WebAuthn ceremony,
                                 vault UI, share dialog, Recovery Kit exporter
storage/     resqd-storage     — MultiCloudVault abstraction (S3 + GCS + Azure)
chain/       resqd-chain       — on-chain canary anchor client
contracts/   contracts         — Solidity ResqdCanaryAnchor (Base Sepolia)
mcp/         resqd-mcp         — Model Context Protocol server (Claude integration)
recover/     resqd-recover     — offline Recovery Kit reader, zero-network
docs/        docs              — RECOVERY_KIT_SPEC.md, JURISDICTION.md,
                                 architecture notes
infra/       infra             — deploy scripts (Lambda, API Gateway, IAM)
```

## Recovering your data (offline)

If you have a Recovery Kit file exported from the RESQD Settings page:

```bash
cargo install --git https://github.com/khiebel/resqd resqd-recover
resqd-recover decrypt -k resqd-recovery-kit-*.json -o ./recovered
```

The tool reads a single JSON file, reconstructs every asset via
Reed-Solomon decode + XChaCha20-Poly1305 decrypt, and writes your
original files to the output directory. It makes no network calls —
not to us, not to AWS, not to anyone. Audit the code in
[`recover/src/main.rs`](./recover/src/main.rs) (under 500 lines) and
run your own copy.

Full format specification:
[`docs/RECOVERY_KIT_SPEC.md`](./docs/RECOVERY_KIT_SPEC.md).

## Trust boundaries

- [`docs/RECOVERY_KIT_SPEC.md`](./docs/RECOVERY_KIT_SPEC.md) — canonical
  data-of-last-resort format and decryption algorithm
- [`docs/JURISDICTION.md`](./docs/JURISDICTION.md) — geo restrictions
  (OFAC + export-control) and appeal path
- [Security Model page](https://resqd.ai/security-model/) — the full
  threat-model and trust-boundary disclosure

## Running your own instance

Everything in this repo is AGPL-3.0. You can stand up your own RESQD
instance against your own AWS account, your own DynamoDB tables, your
own S3 buckets, and your own domain. The geo-restriction middleware
defaults to empty when `RESQD_BLOCKED_COUNTRIES` is unset. See
[`infra/lambda/deploy.sh`](./infra/lambda/deploy.sh) for the deployment
path.

## License

[GNU Affero General Public License v3.0](./LICENSE).

The AGPL is chosen deliberately: if you run a modified copy of RESQD as
a service, you must offer the modified source to your users. This is the
same trust-guarantee we make to ours.

## Security

Please report vulnerabilities via the process in
[`SECURITY.md`](./SECURITY.md).
