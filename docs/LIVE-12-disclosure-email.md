# LIVE-12 disclosure email — draft

**To:** a@byt.pw, khiebel@gmail.com
**From:** khiebel@gmail.com
**Subject:** RESQD alpha — security advisory LIVE-12 (fix deployed)

---

Eric (and Kevin as an audit-trail CC),

Writing to let you know about a security issue in the RESQD alpha that
Dave Freeman — our friendly red-teamer and one of the four 2018
whiteboard co-inventors — found and reported on Friday, April 10. I'm
tracking it internally as LIVE-12 and the fix is already in. Reading
this over coffee is plenty, there's no action for you to take.

## What happened

Three bugs in the Rust API and the Lambda deploy config chained into
a single failure: anyone who found the raw AWS API Gateway URL
(`pjoq4jjjtb.execute-api.us-east-1.amazonaws.com`) could curl
`/admin/users` and receive the users table. Dave demonstrated the
finding against the live alpha during his red-team session.

The three bugs were:

1. The admin endpoints were in the "skip the origin-secret check"
   exemption list of the API middleware. That exemption was
   originally added because admin was supposedly gated by Cloudflare
   Access — which is true at the edge, but false for anyone who
   bypassed Cloudflare entirely by calling the origin directly.

2. The `require_admin()` function trusted the
   `cf-access-authenticated-user-email` header verbatim with no
   allowlist. If the header was absent it fell back to the literal
   string `"admin"`, which the rest of the code accepted as a valid
   admin identity.

3. The `RESQD_ORIGIN_SECRET` environment variable was not required
   by the Lambda deploy script. It happened to be set in production
   at the time of the finding (good), but any future re-deploy from
   a shell without the variable exported would have silently emptied
   it and converted the origin-check middleware into a no-op across
   every non-admin route too. A latent one-unlucky-deploy-away
   failure.

Bugs 1 and 2 were sufficient on their own to enable the
direct-to-origin admin takeover that Dave demonstrated — bug 3 is
the safety net next to them that would have given way on the next
re-deploy. All three are fixed together.

## What was actually exposed

At the moment Dave captured his proof-of-concept (18:14 UTC on
2026-04-10), the `resqd-users` DynamoDB table contained **exactly
two** registered users: you and me. Dave's `/admin/users` dump
returned `{"count":2}`. No other alpha testers had registered a
passkey yet.

For each of the two rows, the following fields were readable:

- email address (yours: `a@byt.pw`, mine: `khiebel@gmail.com`)
- display name
- `storage_used_bytes`
- `has_x25519_identity` (boolean)
- `disabled` (boolean, no)
- `created_at` timestamp

Two email addresses and a handful of operational metadata fields.
No secrets. No keys.

## What was NOT exposed

- **Vault contents.** Every file is erasure-coded + XChaCha20 +
  ML-KEM-768 encrypted **in the browser** before it ever touches the
  API. The keys live in your passkey's PRF extension and are never
  transmitted or stored server-side. The admin endpoints never see
  plaintext and never see key material — that is the core product
  guarantee and it held.
- **Passkey credentials.** Never leave your device.
- **Canary chains.** Blockchain-anchored on Base Sepolia; tampering
  would be visible after the fact.
- **Per-asset keys, ring keys, recovery kit keys.** All client-side,
  all sealed under your master key, all invisible to the server.

## What Dave actually did

Exactly what a friendly red-teamer is supposed to do: he hit the bug
once to prove it was real, captured the `/admin/users` response for
his report, told me immediately, and has not distributed it or
retained it outside his finding write-up. The reason he had alpha
access in the first place is that I gave him admin access on April 10
with exactly this kind of exercise in mind.

## The fix

Committed on April 10 as `54ed7ca`. Three pieces:

1. `/admin` removed from the origin-secret exemption.
2. `require_admin()` now enforces a `RESQD_ADMIN_EMAILS` server-side
   allowlist, fail-closed, with no header fallback and no default
   identity.
3. `RESQD_ORIGIN_SECRET` and `RESQD_ADMIN_EMAILS` are now required
   deploy-time environment variables — the deploy script aborts if
   either is missing.

On top of that, the API now ships a tower middleware that sets HSTS,
X-Frame-Options, X-Content-Type-Options, a locked-down CSP
(`default-src 'none'`), and the cross-origin isolation headers on
every response.

Pending operational work that doesn't affect you:

- Rotate the JWT and origin secrets (both done as part of redeploy).
- Add an AWS WAFv2 rule that restricts API Gateway to Cloudflare IP
  ranges only — so even if a future middleware bug reappears, the
  network layer blocks direct-to-origin requests at the edge.
- Frontend CSP headers on `app.resqd.ai` via Cloudflare Pages.

## What you should do

Nothing. Really. I considered asking you to rotate something, but
there's nothing on your side that's compromised — all the crypto
material that matters to the product is device-bound and was never
reachable.

One thing you may notice: your existing RESQD session will be logged
out the next time you open the site, because the session-signing key
is being rotated as part of the redeploy. You'll log back in with
your passkey, as usual.

## Post-mortem note for myself

Three bugs, one chain. The shared failure mode across all three was
the same: *"CF Access is the gate" was in the mental model, but the
gate was in the wrong place.* CF Access runs at the edge; the origin
was reachable. Any time a defense depends on traffic arriving via a
specific path, there has to be a network-layer enforcement of that
path — not just a middleware assumption that the path was taken.
That's what the WAFv2 lockdown (coming in the runbook) is for: belt
AND suspenders, not just one or the other.

A full writeup is being published as a GitHub security advisory on
`khiebel/resqd` — the repo is AGPL-3.0 and the community norm is to
disclose, credit the finder, and document the fix commit. Dave will
be credited in the acknowledgements.

Thanks for being part of the alpha. The whole point of an alpha with
four of the original whiteboard people is to let a friendly red-teamer
find the bugs before an unfriendly one does. The system worked exactly
as intended here.

Kevin
