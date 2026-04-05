#!/usr/bin/env bash
# Deploy resqd-api-lambda to AWS.
#
# What this does (idempotent — safe to re-run):
#   1. Create IAM role `resqd-api-role` (if missing) with AWSLambdaBasicExecutionRole
#      + inline policy for the vault S3 bucket.
#   2. Package the already-built binary from `target/lambda/resqd-api-lambda/bootstrap`
#      into a zip.
#   3. Create or update Lambda function `resqd-api` (arm64, provided.al2023).
#   4. Create or update an API Gateway HTTP API `resqd-api` with $default -> Lambda.
#   5. Add the invoke permission so API Gateway can call the Lambda.
#   6. Print the public API endpoint.
#
# Prereqs:
#   - `cargo lambda build --release --arm64 --bin resqd-api-lambda` ran successfully.
#   - AWS CLI configured with permissions for iam, lambda, apigatewayv2.
#   - The environment variables below are set in your shell when you run the script.
#
# Usage:
#   export RESQD_CHAIN_SIGNER_KEY=0x...
#   ./deploy.sh
set -euo pipefail

REGION=us-east-1
FUNCTION_NAME=resqd-api
ROLE_NAME=resqd-api-role
API_NAME=resqd-api
ARCH=arm64
RUNTIME=provided.al2023
MEMORY=512
TIMEOUT=30

# Paths
REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
BINARY=$REPO_ROOT/api/target/lambda/resqd-api-lambda/bootstrap
TRUST=$REPO_ROOT/infra/lambda/trust-policy.json
PERMS=$REPO_ROOT/infra/lambda/permissions-policy.json

if [[ ! -f "$BINARY" ]]; then
  echo "error: $BINARY not found. Run: cargo lambda build --release --arm64 --bin resqd-api-lambda" >&2
  exit 1
fi

: "${RESQD_CHAIN_SIGNER_KEY:?RESQD_CHAIN_SIGNER_KEY must be set (hex private key of the on-chain signer)}"

ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
echo "==> Deploying as account $ACCOUNT in $REGION"

# ---------- 1. IAM role ----------
ROLE_ARN=$(aws iam get-role --role-name "$ROLE_NAME" --query 'Role.Arn' --output text 2>/dev/null || true)
if [[ -z "${ROLE_ARN:-}" ]]; then
  echo "==> Creating IAM role $ROLE_NAME"
  ROLE_ARN=$(aws iam create-role \
    --role-name "$ROLE_NAME" \
    --assume-role-policy-document "file://$TRUST" \
    --description "Execution role for resqd-api Lambda" \
    --query 'Role.Arn' --output text)
  aws iam attach-role-policy --role-name "$ROLE_NAME" \
    --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
  echo "==> Waiting 10s for role to propagate..."
  sleep 10
else
  echo "==> IAM role $ROLE_NAME already exists"
fi

aws iam put-role-policy --role-name "$ROLE_NAME" \
  --policy-name "resqd-api-vault-access" \
  --policy-document "file://$PERMS"
echo "==> Inline policy updated"

# ---------- 2. Package ----------
ZIP=$(mktemp -d)/lambda.zip
(cd "$(dirname "$BINARY")" && zip -qj "$ZIP" bootstrap)
echo "==> Packaged $(du -h "$ZIP" | awk '{print $1}')"

# ---------- 3. Lambda function ----------
ENV_VARS="Variables={RESQD_S3_BUCKET=resqd-vault-64553a1a,RESQD_CHAIN_ENABLED=true,RESQD_CHAIN_RPC_URL=https://sepolia.base.org,RESQD_CHAIN_CONTRACT=0xd45453477aa729C157E4840e81F81D4437Ec99f3,RESQD_CHAIN_SIGNER_KEY=$RESQD_CHAIN_SIGNER_KEY,RUST_LOG=info}"

if aws lambda get-function --function-name "$FUNCTION_NAME" --region "$REGION" >/dev/null 2>&1; then
  echo "==> Updating existing function $FUNCTION_NAME"
  aws lambda update-function-code \
    --function-name "$FUNCTION_NAME" \
    --zip-file "fileb://$ZIP" \
    --region "$REGION" >/dev/null
  aws lambda wait function-updated --function-name "$FUNCTION_NAME" --region "$REGION"
  aws lambda update-function-configuration \
    --function-name "$FUNCTION_NAME" \
    --role "$ROLE_ARN" \
    --memory-size "$MEMORY" \
    --timeout "$TIMEOUT" \
    --environment "$ENV_VARS" \
    --region "$REGION" >/dev/null
  aws lambda wait function-updated --function-name "$FUNCTION_NAME" --region "$REGION"
else
  echo "==> Creating function $FUNCTION_NAME"
  aws lambda create-function \
    --function-name "$FUNCTION_NAME" \
    --runtime "$RUNTIME" \
    --architectures "$ARCH" \
    --role "$ROLE_ARN" \
    --handler bootstrap \
    --zip-file "fileb://$ZIP" \
    --memory-size "$MEMORY" \
    --timeout "$TIMEOUT" \
    --environment "$ENV_VARS" \
    --region "$REGION" >/dev/null
  aws lambda wait function-active --function-name "$FUNCTION_NAME" --region "$REGION"
fi

FUNCTION_ARN=$(aws lambda get-function --function-name "$FUNCTION_NAME" --region "$REGION" --query 'Configuration.FunctionArn' --output text)
echo "==> Function ARN: $FUNCTION_ARN"

# ---------- 4. API Gateway HTTP API ----------
API_ID=$(aws apigatewayv2 get-apis --region "$REGION" --query "Items[?Name=='$API_NAME'].ApiId" --output text)
if [[ -z "$API_ID" ]]; then
  echo "==> Creating API Gateway HTTP API $API_NAME"
  API_ID=$(aws apigatewayv2 create-api \
    --name "$API_NAME" \
    --protocol-type HTTP \
    --target "$FUNCTION_ARN" \
    --region "$REGION" \
    --query 'ApiId' --output text)
else
  echo "==> API Gateway API $API_NAME already exists ($API_ID)"
  # Ensure default integration is pointed at the current function
  INT_ID=$(aws apigatewayv2 get-integrations --api-id "$API_ID" --region "$REGION" --query 'Items[0].IntegrationId' --output text 2>/dev/null || echo "")
  if [[ -z "$INT_ID" || "$INT_ID" == "None" ]]; then
    INT_ID=$(aws apigatewayv2 create-integration \
      --api-id "$API_ID" \
      --integration-type AWS_PROXY \
      --integration-uri "$FUNCTION_ARN" \
      --payload-format-version 2.0 \
      --region "$REGION" \
      --query 'IntegrationId' --output text)
    aws apigatewayv2 create-route --api-id "$API_ID" --route-key '$default' --target "integrations/$INT_ID" --region "$REGION" >/dev/null
    aws apigatewayv2 create-stage --api-id "$API_ID" --stage-name '$default' --auto-deploy --region "$REGION" >/dev/null 2>&1 || true
  fi
fi

# ---------- 5. Lambda invoke permission ----------
STATEMENT_ID="apigw-invoke-$API_ID"
aws lambda add-permission \
  --function-name "$FUNCTION_NAME" \
  --statement-id "$STATEMENT_ID" \
  --action lambda:InvokeFunction \
  --principal apigateway.amazonaws.com \
  --source-arn "arn:aws:execute-api:$REGION:$ACCOUNT:$API_ID/*/*" \
  --region "$REGION" 2>/dev/null || echo "==> Invoke permission already exists"

# ---------- 6. Output ----------
ENDPOINT=$(aws apigatewayv2 get-api --api-id "$API_ID" --region "$REGION" --query 'ApiEndpoint' --output text)
echo
echo "======================================================================"
echo "  resqd-api deployed"
echo "  endpoint: $ENDPOINT"
echo "  function: $FUNCTION_NAME"
echo "  api id  : $API_ID"
echo "======================================================================"
echo
echo "Smoke test:"
echo "  curl $ENDPOINT/health"
echo "  echo 'hello vault' | curl -X POST $ENDPOINT/vault --data-binary @-"
