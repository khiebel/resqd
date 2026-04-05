# resqd-api Lambda Deploy

Deployment recipe for `resqd-api-lambda` on AWS Lambda + API Gateway HTTP API.

## Runtime

- **Function name:** `resqd-api`
- **Runtime:** `provided.al2023` (custom Rust binary)
- **Architecture:** arm64 (Graviton — cheaper, faster cold starts)
- **Memory:** 512 MB
- **Timeout:** 30s

## Prereqs

- `cargo-lambda` installed (`brew tap cargo-lambda/cargo-lambda && brew install cargo-lambda`)
- AWS CLI configured with `iam:*`, `lambda:*`, `apigatewayv2:*` permissions
- Contract deployed on Base Sepolia (see `../../../contracts/README.md`)
- `RESQD_CHAIN_SIGNER_KEY` env var set (hex private key of the authorized signer)

## Deploy

```bash
# From the repo root
cd api
cargo lambda build --release --arm64 --bin resqd-api-lambda
cd ../infra/lambda
export RESQD_CHAIN_SIGNER_KEY=0x...
./deploy.sh
```

The script is idempotent — re-run to push new binaries or change config.

## What gets created

| Resource | Name | Notes |
|---|---|---|
| IAM role | `resqd-api-role` | Lambda execution + inline S3 policy for `resqd-vault-64553a1a` |
| Lambda function | `resqd-api` | arm64 provided.al2023 |
| API Gateway HTTP API | `resqd-api` | `$default` route → Lambda |
| Lambda invoke permission | `apigw-invoke-<apiId>` | Lets API Gateway call the function |

Output includes the public endpoint, e.g. `https://xxxxxx.execute-api.us-east-1.amazonaws.com`.

## Smoke test

```bash
./smoke-test.sh https://xxxxxx.execute-api.us-east-1.amazonaws.com
```

Tests `/health`, uploads a payload, fetches it (rotating the canary on Base Sepolia),
and verifies access count. Exits non-zero if anything diverges.

## Multi-cloud note

The Lambda deploys in **S3-only mode** (6 erasure shards across 6 S3 prefixes on the same bucket).
GCS multi-cloud requires either bundling the `gcloud` CLI in a Lambda layer or implementing native
AWS→GCP STS WIF token exchange in the GCS store. Both are possible but not blocking for MVP.
When GCS-on-Lambda is added, set `RESQD_GCS_BUCKET` on the function and redeploy.

## Next: Cloudflare Access + custom domain

Once the raw API endpoint is tested, front it with `api.resqd.ai` via Cloudflare:

1. Add a Cloudflare Access application for `api.resqd.ai` with a policy allowing only `khiebel@gmail.com`
2. Create a CNAME `api.resqd.ai` → API Gateway custom domain (requires ACM cert on the AWS side)
3. Alternative (simpler): Cloudflare Worker that reverse-proxies `api.resqd.ai` → the raw execute-api URL, gated by Access
