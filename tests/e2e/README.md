# RESQD E2E test harness

Headless Playwright runner that exercises the full signup → upload →
fetch → byte-compare → teardown flow against the LIVE `resqd.ai`
frontend. No hardware passkey or human tap required.

## How it bypasses the passkey requirement

Three things, in combination:

1. **CF Access service token** — gates `resqd.ai` from the Cloudflare
   edge. The test adds `CF-Access-Client-Id` + `CF-Access-Client-Secret`
   headers via Playwright `context.route` so only requests to
   `resqd.ai` carry them. Requests to `api.resqd.ai` are left alone so
   their CORS preflights don't trip on unknown request headers. The
   token is scoped to a dedicated Access policy with
   `decision: non_identity` and is safe to rotate.
2. **Chrome CDP virtual WebAuthn authenticator** with the PRF
   extension enabled (`ctap2.1`, `hasPrf: true`,
   `automaticPresenceSimulation: true`). Chrome's virtual authenticator
   generates a fresh EC2 keypair in-memory and signs registration +
   assertion challenges exactly like a hardware passkey would. PRF
   output is delivered to `navigator.credentials.create({prf: ...})`
   so the RESQD client can derive its master key.
3. **Server accepts `none` attestation.** `api/src/auth.rs` calls
   `WebauthnBuilder::new(rp_id, origin)` without overriding attestation
   preference, so the default (`None`) is in effect. This means the
   server will happily register a software-generated credential — no
   Apple/Google/Yubico hardware trust chain required.

## Prerequisites

- Node 20+ (Playwright requires it)
- `npm install` once in `tests/e2e/`
- `npx playwright install chromium` once
- `tests/e2e/.secrets.env` populated with `CF_ACCESS_CLIENT_ID` and
  `CF_ACCESS_CLIENT_SECRET` (gitignored)
- AWS credentials with `dynamodb:DeleteItem` + `GetItem` + `UpdateItem`
  on `resqd-users` (for pre-run cleanup and quota bump)

## Running

```sh
cd tests/e2e
node streaming_roundtrip.mjs                               # 4 MB single-shot path
RESQD_E2E_FILE_SIZE=$((150*1024*1024)) node streaming_roundtrip.mjs   # 150 MB streaming path
```

The test writes a deterministic pseudo-random input file to
`tests/e2e/test-output/roundtrip-input.bin` (reused across runs of the
same size), uploads it through the real frontend, downloads it back
via the fetch page, and compares SHA-256. Exit code 0 on byte-equal
match, 1 on any mismatch, 2 on missing secrets, 3 on unhandled.

## Pre-run cleanup + quota

Because the same test email (`claude-e2e@resqd.ai.test`) is reused
across runs, every run first deletes any existing user row from
`resqd-users` via `aws dynamodb delete-item`. That's idempotent — the
delete is a no-op if the row doesn't exist.

After signup, the runner bumps `storage_quota_bytes` to 2 GB on the
new row so the streaming-path test (150+ MB) doesn't trip the default
100 MB per-user cap. The server's `try_consume_storage` reads this
field on every commit, so the bump takes effect without a redeploy.

## What's covered

- CF Access service token bypass
- Cross-origin CORS: `resqd.ai` → `api.resqd.ai` with credentials
- WebAuthn signup + PRF key derivation in the real React app
- Master key persisted in `sessionStorage`
- Vault upload — single-shot path (`POST /vault/init` + 6 parallel
  PUTs + commit) OR streaming path (`POST /vault/stream/*` + S3
  multipart PUTs + absorption verification), depending on file size
- Chunk 2.1 + 2.2 + 2.3 client-side hashes and content-length passing
  server-side absorption checks
- Track 3 adaptive bandwidth controller running live (visible in
  devtools if you run headed)
- Fetch flow: single-shot erasure reconstruct + decrypt OR streaming
  decode + decrypt per group, depending on manifest mode
- Teardown: user row + S3 blobs cleaned up

## What's NOT covered

- **Ring uploads** — uploading to a family ring isn't exercised.
  Easy to add: drop the ring selector before the file input and
  assert the ring-member fetch path.
- **Large-file multi-GB cases** — MVP holds everything in browser
  memory; adding a 2 GB file would require range-based streaming
  download first.
- **Mobile passphrase fallback** — the signup flow here uses PRF.
  The iOS fallback path (not yet built) would need a different
  signup helper.
- **Proof-of-absorption negative test** — deliberately corrupting a
  shard mid-upload to assert the 422 AbsorptionFailed response.
  A good next add if you want regression coverage on Chunk 2.x.

## Regenerating the service token

```sh
curl -s -H "X-Auth-Email: $CLOUDFLARE_EMAIL" \
     -H "X-Auth-Key: $CLOUDFLARE_API_KEY" \
     -H "Content-Type: application/json" \
     -X POST \
     "https://api.cloudflare.com/client/v4/accounts/$CLOUDFLARE_ACCOUNT_ID/access/service_tokens" \
     -d '{"name":"resqd-e2e-runner","duration":"8760h"}'
```

Update `.secrets.env` with the new `client_id` + `client_secret`,
then update the policy on the RESQD app (id
`85d7c81a-c1ad-4a91-950d-2509eb9a014c`) if the token's UUID changes.
