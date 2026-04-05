# RESQD — Jurisdiction & Geo Restrictions

**Last updated:** 2026-04-05
**Status:** Active on the live API (enforced by Lambda middleware; CF edge
rule pending)

## Summary

RESQD is operated from the United States by an individual ("the operator")
and must comply with US sanctions law and export-control regulations. We
make a **best-effort attempt** to block access from jurisdictions where
providing a strong-crypto privacy service to the general public is either
illegal, sanctioned, or carries meaningful legal risk for the operator.

This is not a technical border — a VPN defeats it in one click. It is a
good-faith compliance posture, documented publicly so our intent is
unambiguous.

## Who is currently blocked

The `RESQD_BLOCKED_COUNTRIES` environment variable on the Lambda controls
the active block list. As of the last update of this document, the list
is expected to include (but the live list in the Lambda env var is
authoritative):

| ISO alpha-2 | Country                      | Primary reason                                       |
|-------------|------------------------------|------------------------------------------------------|
| `CU`        | Cuba                         | US OFAC comprehensive sanctions                      |
| `IR`        | Iran                         | US OFAC comprehensive sanctions                      |
| `KP`        | North Korea                  | US OFAC comprehensive sanctions                      |
| `SY`        | Syria                        | US OFAC comprehensive sanctions                      |
| `RU`        | Russia                       | US sanctions program (post-2022)                     |
| `BY`        | Belarus                      | US sanctions program                                 |
| `CN`        | China (mainland)             | Strong-crypto export restrictions, local law risk    |

Hong Kong, Macau, and Taiwan are **not** on the block list as of this
writing — they are treated as distinct jurisdictions for this purpose.

The operator may adjust the list at any time, without notice, for any
reason, including reacting to new sanctions designations, new
export-control determinations, or perceived changes in legal risk. Every
change to the list is a single deploy of the `RESQD_BLOCKED_COUNTRIES`
env var on the Lambda — there is no format migration or schema change
involved. See the runbook at the bottom of this document.

## What users see

A blocked request to any RESQD endpoint returns HTTP **451 Unavailable For
Legal Reasons** with a JSON body:

```json
{
  "error": "Service not available in your region",
  "code": "geo_blocked",
  "detected_country": "XX",
  "more_info": "https://resqd.ai/jurisdiction/"
}
```

The browser renders this via the marketing site's `/jurisdiction/` page,
which carries a copy of this document in user-friendly prose.

## Enforcement layers

RESQD enforces geo restrictions in (up to) three places:

1. **Cloudflare WAF rule** (preferred, pending deploy).
   Configured in the Cloudflare dashboard on the `resqd.ai` zone. Rejects
   blocked traffic at the edge before it ever reaches the origin.
   Lowest latency, lowest cost, cleanest logs.

2. **Cloudflare Access policy.**
   The invite-only alpha already gates `resqd.ai` + `app.resqd.ai` via
   Access application `85d7c81a-c1ad-4a91-950d-2509eb9a014c`, which is
   allow-list-by-email. Effectively implies geo restriction for now
   (only explicitly invited users can load the app at all), but not
   country-keyed — the block list above still matters the moment
   public signups open.

3. **Lambda middleware.** `api/src/lib.rs::geo_block_middleware` reads
   the `cf-ipcountry` header Cloudflare injects and returns 451 for
   blocked countries. This is the defence-in-depth fallback for the
   "CF rule got deleted / misconfigured" failure mode. Enabled
   whenever `RESQD_BLOCKED_COUNTRIES` is non-empty.

## Behavioural notes & caveats

- **Missing `cf-ipcountry` header = allow.** Local dev, direct-to-Lambda
  smoke tests, and CloudWatch warmup probes all lack the header. Treating
  "missing" as "blocked" would make the ops team lock itself out on every
  iteration. This is load-bearing — don't flip the default.
- **`/health` is always allowed.** Lambda warmup and CloudWatch synthetic
  checks hit `/health`; they must never 451.
- **CORS preflight (`OPTIONS`) is always allowed.** A browser in a
  blocked country otherwise couldn't even render the block page, because
  the preflight to load the 451 JSON would itself 451.
- **The response only echoes the caller's own detected country**, never
  the full block list, so the block list is not exfiltrable via a simple
  probe.
- **No logging of PII.** The Lambda middleware logs only
  `country=XX path=/vault` at `warn` level on block. No IP, no user
  agent, no headers beyond the country code.
- **No persistence of blocks.** The decision is stateless per request.
  A user who visits from a blocked country, gets a 451, and then comes
  back from a non-blocked country on a subsequent request is
  indistinguishable from any other first-time visitor.
- **No signup-time country flag.** The alpha does not collect
  country-of-residence at signup. That's planned for the admin console
  (task #8) as a secondary enforcement point — blocking not just the IP
  at the time of the request, but also denying service to any user whose
  self-declared country ends up on a future block list. Not yet built.

## Appeal path

If you are reading this because RESQD has denied you service and you
believe the determination is wrong — for example, you're travelling from
an allowed country, using a VPN endpoint you don't control, or you're a
US citizen abroad — email `support@resqd.ai`. The operator will review
every appeal individually, in writing, and is willing to add
case-specific exceptions at the Cloudflare Access layer for users who
can establish a legitimate claim to access.

If you are in a country on the block list for reasons that make
legitimate appeal unsafe for you (e.g., the local government would
retaliate for you seeking a US-based privacy service), please don't
send an identifying email. RESQD's threat model takes your safety more
seriously than the operator's compliance posture. Use the open-source
code in the repo to run your own private instance.

## Trust boundary disclosure

The Security Model page on resqd.ai discloses this as a known trust
boundary: we are making a unilateral decision about who we will serve,
in advance of any sanction being imposed directly on an individual user.
If this is a non-starter for you, RESQD is the wrong product, and the
source code is available (see the Open Source section of the Security
Model page) so you can run your own instance against your own S3/GCS
buckets without this layer.

## Runbook — updating the block list

The Lambda env var `RESQD_BLOCKED_COUNTRIES` is a comma-separated list of
uppercase ISO-3166-1 alpha-2 country codes. To update it:

```bash
# Update the env var on the Lambda
aws lambda update-function-configuration \
    --function-name resqd-api \
    --environment "Variables={RESQD_BLOCKED_COUNTRIES=CU,IR,KP,SY,RU,BY,CN,...}" \
    --region us-east-1

# Re-deploy via the normal deploy script to persist the change across
# subsequent code deploys (otherwise the next deploy.sh run will
# stomp it back to the values baked into infra/lambda/deploy.sh)
bash infra/lambda/deploy.sh
```

Update `infra/lambda/deploy.sh`'s env var block at the same time so the
list stays in source control. Every change should be accompanied by a
note here documenting the date, the change, and the rationale.

## Runbook — setting the Cloudflare edge rule (to be completed)

_Pending — dashboard changes not yet applied. When applied:_

1. Cloudflare dashboard → `resqd.ai` zone → Security → WAF → Custom Rules
2. Create rule: `(ip.geoip.country in {"CU" "IR" "KP" "SY" "RU" "BY" "CN"})`
3. Action: `Block` with custom response code 451 and a JSON body
   pointing at `https://resqd.ai/jurisdiction/`
4. Scope: all of `resqd.ai`, `app.resqd.ai`, `api.resqd.ai`
5. Confirm the rule hits by testing from a CF worker running in a
   non-blocked region but spoofing the `cf-ipcountry` header

Keep the Lambda middleware as fallback — do not remove it when the edge
rule lands.

## Change log

| Date         | Change                                                           |
|--------------|------------------------------------------------------------------|
| 2026-04-05   | Initial version. Lambda middleware shipped; CF edge rule pending.|
