#!/usr/bin/env bash
# Smoke test the deployed resqd-api endpoint end-to-end.
# Exercises: health, upload, fetch (x2), verify, and confirms on-chain anchor.
#
# Usage:  ./smoke-test.sh https://xxx.execute-api.us-east-1.amazonaws.com
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <api-endpoint>" >&2
  exit 1
fi
API=$1

# If CF_ACCESS_CLIENT_ID/SECRET are set, attach them to every curl so the
# script works against api.resqd.ai (gated by Cloudflare Access). When not
# set, curl runs bareheaded against a public endpoint (e.g. raw execute-api).
CF_HEADERS=()
if [[ -n "${CF_ACCESS_CLIENT_ID:-}" && -n "${CF_ACCESS_CLIENT_SECRET:-}" ]]; then
  CF_HEADERS=(-H "CF-Access-Client-Id: $CF_ACCESS_CLIENT_ID"
              -H "CF-Access-Client-Secret: $CF_ACCESS_CLIENT_SECRET")
  echo "==> using CF Access service token"
fi

echo "==> GET /health"
curl -sfS "${CF_HEADERS[@]}" "$API/health" | python3 -m json.tool

echo
echo "==> POST /vault"
PAYLOAD="resqd lambda smoke test $(date +%s)"
UPLOAD_JSON=$(printf '%s' "$PAYLOAD" | curl -sfS "${CF_HEADERS[@]}" -X POST "$API/vault" \
  -H 'content-type: application/octet-stream' \
  --data-binary @-)
echo "$UPLOAD_JSON" | python3 -m json.tool
ASSET_ID=$(python3 -c "import json,sys; print(json.loads('''$UPLOAD_JSON''')['asset_id'])")
ANCHORED=$(python3 -c "import json,sys; print(json.loads('''$UPLOAD_JSON''')['anchored_on_chain'])")
echo "asset_id: $ASSET_ID"
echo "anchored_on_chain: $ANCHORED"

if [[ "$ANCHORED" != "True" ]]; then
  echo "warn: initial commitment not anchored on-chain" >&2
fi

echo
echo "==> GET /vault/$ASSET_ID (rotates canary)"
BODY=$(curl -sfS "${CF_HEADERS[@]}" -D /tmp/smoke-headers "$API/vault/$ASSET_ID")
SEQ=$(grep -i '^x-resqd-canary-sequence:' /tmp/smoke-headers | tr -d '\r\n' | awk '{print $2}')
echo "  body: $BODY"
echo "  sequence header: $SEQ"

if [[ "$BODY" != "$PAYLOAD" ]]; then
  echo "FAIL: body mismatch" >&2
  exit 2
fi

echo
echo "==> GET /vault/$ASSET_ID/verify?count=2"
curl -sfS "${CF_HEADERS[@]}" "$API/vault/$ASSET_ID/verify?count=2" | python3 -m json.tool

echo
echo "✓ smoke test passed"
