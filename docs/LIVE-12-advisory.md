# GitHub Security Advisory — LIVE-12

Published as a GitHub Security Advisory on `khiebel/resqd`. Paste this
markdown into the advisory draft at
https://github.com/khiebel/resqd/security/advisories/new.

---

## Title

Unauthenticated admin access via origin-secret exemption + header trust
(LIVE-12)

## Severity

**Critical** — pre-authentication, remote, full admin privilege.

## Affected versions

Every commit up to and including `b77615f`. Fix landed in `54ed7ca` on
2026-04-10.

## Summary

A chain of three independent bugs in the `resqd-api` Lambda enabled a
remote unauthenticated attacker, given knowledge of the raw AWS API
Gateway URL (`pjoq4jjjtb.execute-api.us-east-1.amazonaws.com`), to
call any endpoint under `/admin/*` and obtain the full users table —
email addresses, display names, storage utilisation, identity key
presence, and disabled-flag state — for every user registered with
a passkey in the `resqd-users` DynamoDB table at the time the bug
was exploited.

**Scope at time of finding:** two (2) users registered — one alpha
tester and the repository owner. Both have been notified.

Vault contents, cryptographic keys, and passkey material were NOT
exposed: every byte of user data is erasure-coded and encrypted in
the browser before upload, with keys derived from a WebAuthn PRF
extension that never leaves the client.

## Impact

A remote unauthenticated attacker could:

- enumerate every registered RESQD alpha user by email address,
- read aggregate storage-usage metadata per user,
- observe whether each user had completed the X25519 identity setup,
- observe whether each user was administratively disabled.

The attacker could NOT:

- read any vault contents (client-side encrypted, zero-knowledge to
  the server),
- read any encryption keys or passkey credentials,
- impersonate any user to other RESQD users (passkey-bound sessions),
- post or modify anything (the admin UI is read-only plus a small
  executor-unlock endpoint that was also affected but had no valid
  targets).

## Root cause — the three-bug chain

### Bug 1 — `/admin` in the origin-secret exemption list

`api/src/lib.rs` defined an `origin_secret_middleware` that was
supposed to reject any request that bypassed the Cloudflare reverse-
proxy Worker. The Worker injects a shared secret header
(`x-origin-secret`), and the middleware rejects requests that arrive
without it. `/admin` was on the exemption list under the mistaken
assumption that admin endpoints were gated by Cloudflare Access and
therefore needed no additional origin check:

```rust
|| path.starts_with("/admin")  // <-- REMOVED
```

Cloudflare Access only runs at the edge. A direct-to-origin caller
bypasses Access entirely and therefore bypasses this "outer gate"
the admin code assumed existed.

### Bug 2 — `require_admin()` trusted the header, with a fallback

`api/src/admin.rs` extracted the admin identity from
`cf-access-authenticated-user-email` with no allowlist check and a
fallback to the literal string `"admin"` if the header was missing:

```rust
fn require_admin(headers: &HeaderMap) -> Result<String, Response> {
    let email = headers
        .get("cf-access-authenticated-user-email")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("admin")   // <-- unconditional admin grant
        .to_string();
    Ok(email)
}
```

Any request that reached the function — whether via a forged header
or by omitting the header entirely — was treated as an authorized
admin.

### Bug 3 — `RESQD_ORIGIN_SECRET` never set in the deploy script

`infra/lambda/deploy.sh` never exported `RESQD_ORIGIN_SECRET` into
the Lambda environment, so the middleware's early return clause
```rust
let Some(ref expected) = state.config.origin_secret else {
    return next.run(req).await;
};
```
fired on every request in production. In other words, even the
non-exempted routes were not enforcing the origin secret — the
middleware was a silent no-op for the entire Lambda.

### The chain

Reproduction was a single curl:

```
curl https://pjoq4jjjtb.execute-api.us-east-1.amazonaws.com/admin/users
```

No headers, no auth, no CF Access cookie. Bug 3 meant the origin-secret
middleware skipped the request. Bug 1 would have exempted it anyway.
Bug 2 treated the missing-header case as "admin" identity and let the
handler run. The handler returned the full users table.

Any single one of the three bugs, fixed, would have broken the chain.

## Discovery

Reported on 2026-04-10 by **Dave Freeman** in a friendly red-team
exercise. Dave had been given Cloudflare Access to the RESQD alpha
domain earlier the same day specifically so that he could exercise
the live system and report findings like this before a hostile
attacker did. He demonstrated the bug against production, captured
only the minimum evidence needed to characterise the finding, and
disclosed privately to the repository owner. The system worked as
intended.

**Timeline:**

- 2026-04-10 ~14:00 UTC — Dave given CF Access to `resqd.ai` and
  `resqd.ai/admin/` for alpha testing.
- 2026-04-10 18:14 UTC — Dave dumps `/admin/users` directly from the
  AWS API Gateway URL without any Cloudflare cookie or header; the
  Lambda returns `{"count":2}` with the two rows then in the users
  table.
- 2026-04-10 ~19:30 UTC — Finding reported.
- 2026-04-10 ~20:00 UTC — Fix committed as `54ed7ca`.
- 2026-04-10 after deploy — Dave re-runs the original reproduction
  commands; all four probes return 403 at either the WAF or the
  Lambda middleware.

## Fix

Commit `54ed7ca` (2026-04-10). Three code changes + two deploy-
script additions:

1. `/admin` removed from the origin-secret exemption list in
   `api/src/lib.rs`.
2. `require_admin()` in `api/src/admin.rs` rewritten to enforce a
   `RESQD_ADMIN_EMAILS` server-side allowlist, fail-closed, with no
   header fallback and no default identity. Case-insensitive email
   comparison.
3. New `security_headers_middleware` in `api/src/lib.rs` sets HSTS,
   `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`,
   `Referrer-Policy: strict-origin-when-cross-origin`, a locked-down
   `Content-Security-Policy: default-src 'none'; frame-ancestors
   'none'; base-uri 'none'`, `Cross-Origin-Resource-Policy`,
   `Cross-Origin-Opener-Policy`, and a `Permissions-Policy` that
   denies camera/microphone/geolocation/payment.
4. `infra/lambda/deploy.sh` now requires `RESQD_ORIGIN_SECRET` and
   `RESQD_ADMIN_EMAILS` as deploy-time environment variables and
   passes them through to the Lambda's `Variables` map. The deploy
   aborts early if either is missing.

Additional defense-in-depth work that is operational, not code:

- AWS WAFv2 regional Web ACL attached to the HTTP API stage, with a
  default-block action and an explicit ALLOW for the canonical
  Cloudflare IPv4/IPv6 ranges. This closes the direct-to-origin path
  at the network layer so any future middleware regression fails
  safely.
- `RESQD_JWT_SECRET` rotated. This invalidates any forged session
  tokens that may have been minted against the old key, and
  transparently logs existing users out on next request.
- `RESQD_ORIGIN_SECRET` rotated as part of the same redeploy and
  updated in the Cloudflare Worker via `wrangler secret put
  ORIGIN_SECRET`.
- Frontend (`app.resqd.ai`, Cloudflare Pages) gains a `_headers` file
  that serves an HTML-origin CSP, HSTS, and the same X-Frame /
  referrer / permissions policies.

The full runbook is in `docs/LIVE-12-runbook.md`.

## Data affected

**Exactly two** rows of the `resqd-users` DynamoDB table — the two
users who had registered a passkey at the moment Dave captured the
`/admin/users` response (18:14 UTC, 2026-04-10). For each row, the
following fields were readable:

- `email`
- `display_name`
- `user_id`
- `created_at`
- `storage_used_bytes`
- `has_x25519_identity` (boolean)
- `disabled` (boolean)

**No byte of user vault content was accessible** — every vault is
erasure-coded and encrypted in the browser with keys derived from a
WebAuthn PRF extension that never leaves the client device. **No key
material was accessible** — the server is zero-knowledge to both
the per-asset encryption keys and the passkey credentials.

The two affected users have been notified privately. Neither is
required to take any action; the JWT secret rotation in the fix
will transparently log them out on next request, as a belt-and-
suspenders invalidation of any session tokens that might have been
forged against the old key (no evidence any were).

## CWE mappings

- **CWE-287** Improper Authentication
- **CWE-290** Authentication Bypass by Spoofing
- **CWE-269** Improper Privilege Management
- **CWE-863** Incorrect Authorization
- **CWE-306** Missing Authentication for Critical Function — once
  bugs 1 and 3 lined up, no authentication ran at all for the
  `/admin/*` endpoints; this captures the "door wide open" shape
  better than CWE-287 alone.
- **CWE-1188** Initialization of a Resource with an Insecure
  Default — Bug 3 is textbook 1188: `RESQD_ORIGIN_SECRET` absent
  from the deploy environment defaulted to "middleware no-op"
  instead of "fail closed." Useful grep target for readers who want
  to audit their own deploy scripts for the same antipattern.

## Acknowledgements

Thank you to **Dave Freeman** for the report, for the
proof-of-concept, and for the friendly red-teaming posture that
made this discovery possible on day one of alpha access instead of
after launch.

Thank you to the three other 2018 whiteboard co-inventors — Eric
Hill, Jake Habel, Paul Manaloto — for being patient alpha testers
and for agreeing to receive an advisory about a finding you had no
action to take on.

## References

- Fix commit: https://github.com/khiebel/resqd/commit/54ed7ca
- Runbook: `docs/LIVE-12-runbook.md`
- Disclosure email: `docs/LIVE-12-disclosure-email.md`
