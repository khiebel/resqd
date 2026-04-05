# Contributing to RESQD

Thanks for your interest. This is an open-source alpha run by one
person on evenings and weekends; expect slow responses and strong
opinions about scope.

## What I want

- **Security issues** — see [`SECURITY.md`](./SECURITY.md). These
  always jump to the top of the queue.
- **Bug reports with a reproduction** — the smallest file/input that
  triggers the problem, the expected vs actual behaviour, the
  browser or environment.
- **Compatibility reports** for the offline recovery path. If you
  downloaded a Recovery Kit and `resqd-recover decrypt` failed on
  your platform, please file an issue with the kit version and your
  OS / Rust version.
- **Third-party readers of the Recovery Kit format.** The format is
  versioned and documented in
  [`docs/RECOVERY_KIT_SPEC.md`](./docs/RECOVERY_KIT_SPEC.md). A Python
  or Go or JavaScript reader that can decrypt a v1 kit would be
  genuinely useful to the ecosystem, and exactly the kind of thing
  the trust model invites.
- **Documentation fixes** — typos, broken links, inaccurate
  architecture descriptions.

## What I'm wary of

- **New features.** RESQD is intentionally a small product. Every new
  surface is a new trust boundary. I'd rather ship five things well
  than fifty things halfway. If you have an idea, open an issue to
  discuss before investing in a PR.
- **Replacing crypto primitives.** The choices in
  [`core/Cargo.toml`](./core/Cargo.toml) are deliberate. XChaCha20 is
  chosen over AES-GCM for nonce misuse resistance, BLAKE3 over
  SHA-256 for speed, ML-KEM-768 for post-quantum, Argon2id for
  passphrase hardening. Swaps require both a security argument and a
  migration story for existing vaults.
- **New cloud backends** with their own auth stories. The
  `MultiCloudVault` abstraction exists specifically so we can add
  more without reshaping the core, but each one needs its own
  integration test suite before shipping.

## Before opening a PR

1. **Read the relevant spec.** For Recovery Kit work, read
   [`docs/RECOVERY_KIT_SPEC.md`](./docs/RECOVERY_KIT_SPEC.md). For
   sharing work, read
   [`docs/JURISDICTION.md`](./docs/JURISDICTION.md) and the comments
   in [`api/src/handlers.rs`](./api/src/handlers.rs).
2. **Match the existing style.** Rust code uses `rustfmt` defaults;
   TypeScript uses the Next.js + Tailwind conventions already in the
   repo. Comments should explain *why* a non-obvious decision was
   made, not *what* the code does.
3. **Tests.** New crypto code needs unit tests that cover happy path,
   domain-separation, and failure modes. See
   [`core/src/crypto/share.rs`](./core/src/crypto/share.rs) for the
   pattern.
4. **No secrets in commits.** Grep your diff. Grep your commits. The
   repo has no history of secrets and we'd like to keep it that way.
5. **Sign off.** Every commit should include a
   `Signed-off-by: Your Name <email@example.com>` trailer indicating
   you accept the AGPL-3.0 terms for your contribution.

## License

By contributing, you agree that your contributions will be licensed
under the [GNU Affero General Public License v3.0](./LICENSE). The
AGPL is chosen deliberately — if someone runs a modified copy of
RESQD as a service, their users should be able to see the source of
what's running.

## Coordination

- File issues on GitHub for public discussion.
- For private coordination before a fix or a disclosure, email
  `security@resqd.ai` or the address in [`SECURITY.md`](./SECURITY.md).
- This is not a high-traffic project. Please be patient.
