#!/usr/bin/env bash
# Drive a live kumomiru discovery without putting credentials in shell history.
# Usage:
#   AWS_REGION=us-east-1 ./scripts/live-scan.sh            # uses current AWS CLI creds/profile
#   ./scripts/live-scan.sh us-east-1                       # region as arg
#
# It reads credentials from the AWS CLI's resolved chain (env, profile, SSO),
# builds the request body with jq, POSTs to the local server, and writes the
# resulting graph to live-map.json (gitignored).
set -euo pipefail

REGION="${1:-${AWS_REGION:-${AWS_DEFAULT_REGION:-}}}"
if [[ -z "$REGION" ]]; then
  echo "No region. Pass one: ./scripts/live-scan.sh us-east-1" >&2
  exit 1
fi

SERVER="${KUMOMIRU_SERVER:-http://127.0.0.1:4000}"

# Resolve credentials via the AWS CLI (works with env keys, profiles, SSO).
CREDS_JSON="$(aws configure export-credentials --format process 2>/dev/null || true)"
if [[ -z "$CREDS_JSON" ]]; then
  echo "Could not export credentials. Is the AWS CLI configured? Try: aws sts get-caller-identity" >&2
  exit 1
fi

AKID="$(echo "$CREDS_JSON"  | jq -r '.AccessKeyId')"
SECRET="$(echo "$CREDS_JSON" | jq -r '.SecretAccessKey')"
TOKEN="$(echo "$CREDS_JSON"  | jq -r '.SessionToken // empty')"

# Build body (token included only if present).
BODY="$(jq -nc \
  --arg ak "$AKID" --arg sk "$SECRET" --arg tok "$TOKEN" --arg region "$REGION" \
  '{accessKeyId:$ak, secretAccessKey:$sk, region:$region} + (if $tok != "" then {sessionToken:$tok} else {} end)')"

echo "Posting live discovery for region $REGION to $SERVER ..."
HTTP_CODE="$(curl -s -o live-map.json -w '%{http_code}' \
  -X POST "$SERVER/map/live" \
  -H 'content-type: application/json' \
  --data "$BODY")"

echo "HTTP $HTTP_CODE"
if [[ "$HTTP_CODE" == "200" ]]; then
  echo "Wrote live-map.json:"
  jq '{nodes: (.nodes|length), edges: (.edges|length), findings: (.findings|length), source: .meta.source}' live-map.json
else
  echo "Response:"; cat live-map.json; echo
fi
