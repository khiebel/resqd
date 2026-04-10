# LIVE-12 — Admin takeover remediation runbook

**Severity:** Critical (unauthenticated full admin access)
**Reported:** 2026-04-10 by Dave Freeman (friendly red-team)
**Fixed in:** `54ed7ca` (Rust side) + this runbook (ops side)
**Repo policy:** Public advisory on GitHub (AGPL-3.0)

---

## The short story

Three code bugs chained into unauthenticated admin access on
`api.resqd.ai`. Anyone who discovered the direct API Gateway URL could
`curl /admin/users` and receive the entire users table (emails, display
names, storage usage, identity key presence). Vault contents remained
E2E encrypted and inaccessible — keys live in the browser.

The code bugs are fixed in commit `54ed7ca`. The remaining work — AWS
WAFv2 lockdown, secret rotation, Lambda redeploy, CF Worker hardening —
has to happen at the infra layer and is tracked below as a 30-minute
checklist.

---

## 30-minute remediation checklist

**Do these in order.** Each step has a verification command so you
know it worked before moving to the next.

```
[ ]  1. Generate new secrets                              (1 min)
[ ]  2. Set Worker ORIGIN_SECRET to the new value         (2 min)
[ ]  3. Verify Worker injection                           (1 min)
[ ]  4. Export env vars for Lambda deploy                 (1 min)
[ ]  5. cargo lambda build                                (5 min)
[ ]  6. ./infra/lambda/deploy.sh (Lambda redeploy)        (2 min)
[ ]  7. Verify /admin is gated via the API Gateway URL    (1 min)
[ ]  8. Verify /admin still works via api.resqd.ai        (1 min)
[ ]  9. Create AWS WAFv2 Cloudflare IP set                (5 min)
[ ] 10. Attach WebACL to the API Gateway stage            (2 min)
[ ] 11. Verify direct-to-origin now returns 403           (1 min)
[ ] 12. Cloudflare Pages _headers CSP/HSTS                (3 min)
[ ] 13. Purge Cloudflare cache                            (1 min)
[ ] 14. Send disclosure email to Eric + Kevin             (2 min)
[ ] 15. Publish GitHub security advisory                  (2 min)
```

---

## Step 1 — Generate new secrets

Fresh values for `RESQD_JWT_SECRET` and `RESQD_ORIGIN_SECRET`. Rotating
the JWT secret invalidates all existing sessions, which is the point —
if anyone minted a forged token against the old secret, it stops
working.

```sh
export RESQD_JWT_SECRET=$(openssl rand -base64 48)
export RESQD_ORIGIN_SECRET=$(openssl rand -base64 48)
echo "JWT:    ${RESQD_JWT_SECRET:0:12}..."
echo "ORIGIN: ${RESQD_ORIGIN_SECRET:0:12}..."
```

Save both somewhere safe (`~/private/resqd-secrets.env` is fine) —
you'll need them again on the next deploy.

## Step 2 — Update the Cloudflare Worker secret

The Worker at `infra/worker/` injects `x-origin-secret` from its
`ORIGIN_SECRET` secret binding. Update it to match.

```sh
cd /Users/khiebel/CodeBucket/resqd/infra/worker
echo -n "$RESQD_ORIGIN_SECRET" | wrangler secret put ORIGIN_SECRET
```

Wrangler will ask you to confirm the worker name; it's `resqd-api-proxy`.

## Step 3 — Verify the Worker is injecting the new secret

```sh
curl -i https://api.resqd.ai/health \
  --cf-access-client-id "$CF_ACCESS_CLIENT_ID" \
  --cf-access-client-secret "$CF_ACCESS_CLIENT_SECRET" \
  | head -5
```

Should return `200`. If it returns `403 origin_bypass`, the Worker
redeploy hasn't propagated yet — wait 15 seconds and retry.

## Step 4 — Export env vars for the Lambda deploy

The updated `deploy.sh` requires all of these or it aborts.

```sh
cd /Users/khiebel/CodeBucket/resqd
export RESQD_CHAIN_SIGNER_KEY=$(cat infra/.chain-signer-key)   # wherever you keep it
export RESQD_JWT_SECRET        # from step 1
export RESQD_ORIGIN_SECRET     # from step 1
export RESQD_ADMIN_EMAILS="khiebel@gmail.com"  # start minimal — expand per row below
```

**Who should be on the admin allowlist on day one:** only `khiebel@gmail.com`.
Add alpha testers to the allowlist only after explicit per-person decision.
The tester allow-list (Kevin, Eric, Jake, Paul, Dave) gates the main site,
not the admin console. This separation is intentional — see the Admin
vs user Access separation item in `project_resqd_next.md`.

## Step 5 — Build the Lambda

```sh
cd /Users/khiebel/CodeBucket/resqd/api
cargo lambda build --release --arm64 --bin resqd-api-lambda
```

Should finish in a few minutes. Output at
`target/lambda/resqd-api-lambda/bootstrap`.

## Step 6 — Redeploy the Lambda

```sh
cd /Users/khiebel/CodeBucket/resqd
./infra/lambda/deploy.sh
```

This updates the function code AND environment variables in a single
call — the new JWT secret, the new origin secret, and the admin
allowlist all land at the same time.

## Step 7 — Verify /admin is gated from the direct API Gateway URL

This is the smoke test that proves the bug is dead. Before, this
returned user data. Now it should return `403`.

```sh
curl -i https://pjoq4jjjtb.execute-api.us-east-1.amazonaws.com/admin/users
# expect: HTTP/2 403
# body:  {"error":"Forbidden","code":"origin_bypass"}
```

And a second test — even with a forged CF Access header, it should
still fail because the origin secret isn't present:

```sh
curl -i https://pjoq4jjjtb.execute-api.us-east-1.amazonaws.com/admin/users \
  -H "cf-access-authenticated-user-email: khiebel@gmail.com"
# expect: HTTP/2 403
```

If either of those returns a 200, STOP. Something is wrong with the
deploy. Check `aws lambda get-function-configuration --function-name resqd-api`
and confirm `RESQD_ORIGIN_SECRET` is in the `Environment.Variables` map.

## Step 8 — Verify /admin still works through api.resqd.ai

```sh
# Browser: https://resqd.ai/admin/ — should load the admin console
# CLI (with your CF Access cookie from the browser session):
curl -i https://api.resqd.ai/admin/users -b "CF_Authorization=$CF_ACCESS_COOKIE"
# expect: HTTP/2 200
```

## Step 9 — Create a WAFv2 Cloudflare IP set

This is the belt to Step 6's suspenders: even if someone in the future
re-introduces a middleware bug, the network layer will stop them from
reaching the origin from non-Cloudflare IPs.

**Important:** API Gateway HTTP APIs do NOT support resource policies
(that's a REST API feature). The AWS-native way is AWS WAFv2 attached
to the HTTP API stage.

```sh
# Pull the canonical Cloudflare IP ranges
curl -s https://www.cloudflare.com/ips-v4/ -o /tmp/cf-ipv4.txt
curl -s https://www.cloudflare.com/ips-v6/ -o /tmp/cf-ipv6.txt

# Format as JSON arrays for the AWS CLI
CF_IPV4=$(cat /tmp/cf-ipv4.txt | jq -R . | jq -s .)
CF_IPV6=$(cat /tmp/cf-ipv6.txt | jq -R . | jq -s .)

# Create the IPv4 set
aws wafv2 create-ip-set \
  --region us-east-1 \
  --scope REGIONAL \
  --name cloudflare-ipv4 \
  --ip-address-version IPV4 \
  --addresses "$CF_IPV4" \
  --description "Cloudflare public IPv4 ranges — gated by RESQD_ORIGIN_SECRET belt"

# Create the IPv6 set
aws wafv2 create-ip-set \
  --region us-east-1 \
  --scope REGIONAL \
  --name cloudflare-ipv6 \
  --ip-address-version IPV6 \
  --addresses "$CF_IPV6" \
  --description "Cloudflare public IPv6 ranges — gated by RESQD_ORIGIN_SECRET belt"

# Capture the ARNs
CF_V4_ARN=$(aws wafv2 list-ip-sets --scope REGIONAL --region us-east-1 \
  --query "IPSets[?Name=='cloudflare-ipv4'].ARN" --output text)
CF_V6_ARN=$(aws wafv2 list-ip-sets --scope REGIONAL --region us-east-1 \
  --query "IPSets[?Name=='cloudflare-ipv6'].ARN" --output text)

echo "v4: $CF_V4_ARN"
echo "v6: $CF_V6_ARN"
```

## Step 10 — Create the Web ACL and attach it to the API Gateway stage

```sh
# Create the Web ACL with a default BLOCK action and one rule that
# ALLOWs either Cloudflare IPv4 or IPv6.
cat > /tmp/resqd-webacl.json <<JSON
{
  "Name": "resqd-api-cf-only",
  "Scope": "REGIONAL",
  "DefaultAction": { "Block": {} },
  "Description": "Only allow Cloudflare source IPs to reach the resqd-api HTTP API",
  "Rules": [
    {
      "Name": "allow-cloudflare",
      "Priority": 0,
      "Action": { "Allow": {} },
      "Statement": {
        "OrStatement": {
          "Statements": [
            { "IPSetReferenceStatement": { "ARN": "$CF_V4_ARN" } },
            { "IPSetReferenceStatement": { "ARN": "$CF_V6_ARN" } }
          ]
        }
      },
      "VisibilityConfig": {
        "SampledRequestsEnabled": true,
        "CloudWatchMetricsEnabled": true,
        "MetricName": "allow-cloudflare"
      }
    }
  ],
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "resqd-api-cf-only"
  }
}
JSON

# Shell-expand the ARN placeholders
envsubst < /tmp/resqd-webacl.json > /tmp/resqd-webacl.expanded.json

aws wafv2 create-web-acl \
  --region us-east-1 \
  --cli-input-json "file:///tmp/resqd-webacl.expanded.json"

WEBACL_ARN=$(aws wafv2 list-web-acls --scope REGIONAL --region us-east-1 \
  --query "WebACLs[?Name=='resqd-api-cf-only'].ARN" --output text)
echo "WebACL: $WEBACL_ARN"

# Attach to the API Gateway stage
API_ID=pjoq4jjjtb
STAGE_ARN="arn:aws:apigateway:us-east-1::/restapis/$API_ID/stages/\$default"
# NOTE: HTTP APIs use apigateway (not apigatewayv2) ARN format for WAFv2.
# If this fails with "resource not found", list stages to confirm the
# stage name:
#   aws apigatewayv2 get-stages --api-id $API_ID --region us-east-1

aws wafv2 associate-web-acl \
  --region us-east-1 \
  --web-acl-arn "$WEBACL_ARN" \
  --resource-arn "$STAGE_ARN"
```

## Step 11 — Verify the direct-to-origin path is closed at the network layer

```sh
curl -i https://pjoq4jjjtb.execute-api.us-east-1.amazonaws.com/health
# expect: HTTP/2 403 (WAF block, reason: not on allow-list)
```

Your local IP is not on the Cloudflare IP set, so even /health — which
bypasses the Lambda middleware — should be blocked at the WAF.

## Step 12 — Cloudflare Pages hardening for app.resqd.ai

The frontend lives on Cloudflare Pages and does not go through the
reverse-proxy Worker. Add a `_headers` file to the Next.js `public/`
dir so Pages serves a proper CSP / HSTS / X-Frame-Options.

Create `web/public/_headers`:

```
/*
  Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
  X-Content-Type-Options: nosniff
  X-Frame-Options: DENY
  Referrer-Policy: strict-origin-when-cross-origin
  Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()
  Content-Security-Policy: default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self' https://api.resqd.ai https://sepolia.base.org; frame-ancestors 'none'; base-uri 'self'; form-action 'self'
  Cross-Origin-Opener-Policy: same-origin
```

**Notes on the CSP:** `'wasm-unsafe-eval'` is required for the Rust-
compiled crypto core. `'unsafe-inline'` in style-src is a Tailwind
concession; we can tighten to `'unsafe-hashes'` with SRI later if
needed. `connect-src` covers the API + the Base RPC — add any future
endpoints as they come online. Nonce-based CSP on the HTML itself is
a future hardening step that requires a Cloudflare Worker in front of
Pages; the header-based version above is the 80/20.

```sh
cd /Users/khiebel/CodeBucket/resqd/web
# Deploy via your usual Pages flow — e.g.:
npm run build
wrangler pages deploy out --project-name resqd-app
```

## Step 13 — Purge Cloudflare cache for resqd.ai

```sh
curl -X POST "https://api.cloudflare.com/client/v4/zones/20fc4a4faa1c0b70b0b5ff5893abd24b/purge_cache" \
  -H "X-Auth-Email: $CLOUDFLARE_EMAIL" \
  -H "X-Auth-Key: $CLOUDFLARE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"purge_everything":true}'
```

## Step 14 — Send disclosure email

See `docs/LIVE-12-disclosure-email.md` for the draft. Two recipients:
`a@byt.pw` (Eric) and `khiebel@gmail.com` (Kevin, as a receipt for the
audit trail).

## Step 15 — Publish GitHub security advisory

See `docs/LIVE-12-advisory.md` for the draft. Since the repo is
AGPL-3.0, publishing is the right call — it sets norms, credits Dave,
and documents the fix commit.

1. Go to https://github.com/khiebel/resqd/security/advisories/new
2. Copy the advisory markdown from `docs/LIVE-12-advisory.md`
3. Set severity to **Critical**
4. Assign CWEs: CWE-287 (broken auth), CWE-290 (trust headers), CWE-269 (privilege mgmt)
5. Credit Dave Freeman in the acknowledgements
6. Publish

---

## What was NOT affected

Leave these in the mental model of the incident so you don't
inadvertently scope it bigger than it was:

- **Vault contents.** All file bytes are erasure-coded + XChaCha20
  + ML-KEM encrypted client-side in the browser. The admin endpoints
  never see plaintext or keys.
- **Passkey private keys.** Device-bound, never leave the client.
- **Canary chains.** Blockchain-anchored on Base Sepolia; tampering
  would be detectable.
- **Per-user encryption keys.** Sealed under the user's passkey PRF
  and never touch the server.

What WAS exposed in `GET /admin/users`:

- email addresses of every registered tester
- display names
- `storage_used_bytes`
- `has_x25519_identity` (boolean)
- `disabled` (boolean)
- `created_at` (unix timestamp)

That's aggregate metadata and the email addresses of five testers
(Kevin, Eric, Jake if he'd signed up by then, Paul if he'd signed up,
Dave himself). Nothing cryptographically sensitive.
