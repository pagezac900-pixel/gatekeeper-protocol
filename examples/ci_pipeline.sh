#!/usr/bin/env bash
# ci_pipeline.sh — Gatekeeper gate before deploying AI-generated code to Vercel
#
# Drop this script into .github/scripts/gatekeeper-gate.sh and call it from
# your GitHub Actions workflow before the deploy step.
#
# Example .github/workflows/deploy.yml:
#
#   jobs:
#     deploy:
#       runs-on: ubuntu-latest
#       steps:
#         - uses: actions/checkout@v4
#
#         - name: Build (locally, so we can gate before deploy)
#           run: vercel build --prod --token=${{ secrets.VERCEL_TOKEN }}
#
#         - name: Gatekeeper approval gate
#           env:
#             GATEKEEPER_BIN:         ./gatekeeper
#             GATEKEEPER_PAYLOAD:     .vercel/output/config.json
#             GATEKEEPER_DESCRIPTION: "Deploy AI-generated build to Vercel production"
#             GATEKEEPER_KEY:         ~/.config/gatekeeper/ci.key
#           run: bash .github/scripts/gatekeeper-gate.sh
#
#         - name: Deploy pre-built output  (only reached if gate passed)
#           run: vercel deploy --prebuilt --prod --token=${{ secrets.VERCEL_TOKEN }}
#
# Notes:
#   • vercel build + vercel deploy --prebuilt separates build from deploy,
#     which is the correct pattern for custom CI gates.
#   • The Gatekeeper gate runs AFTER the build so the approver sees the exact
#     artifact (config.json / build manifest) that will be deployed.
#   • VERCEL_TOKEN, VERCEL_ORG_ID, VERCEL_PROJECT_ID must be set as
#     GitHub Actions secrets.

set -euo pipefail

BINARY="${GATEKEEPER_BIN:-gatekeeper}"
DESCRIPTION="${GATEKEEPER_DESCRIPTION:-Deploy AI-generated code to production}"
PAYLOAD_FILE="${GATEKEEPER_PAYLOAD:-deploy_manifest.json}"
TOKEN_OUT="${GATEKEEPER_TOKEN_OUT:-/tmp/gatekeeper_token.json}"
KEY_FILE="${GATEKEEPER_KEY:-${HOME}/.config/gatekeeper/session.key}"

# ── Sanity checks ─────────────────────────────────────────────────────────────

if ! command -v "$BINARY" &>/dev/null; then
  echo "ERROR: gatekeeper binary not found at '$BINARY'" >&2
  echo "       Build with: cargo build --release" >&2
  echo "       Then copy target/release/gatekeeper into your repo or PATH." >&2
  exit 2
fi

if [ ! -f "$PAYLOAD_FILE" ]; then
  echo "ERROR: payload file '$PAYLOAD_FILE' not found." >&2
  echo "       Run 'vercel build --prod' first to generate .vercel/output/." >&2
  exit 2
fi

# ── Gatekeeper gate ───────────────────────────────────────────────────────────

echo ""
echo "=== GATEKEEPER: Human approval required before deploying AI-generated code ==="
echo ""

TOKEN_JSON=$(
  "$BINARY" propose "$DESCRIPTION" "$PAYLOAD_FILE" --key "$KEY_FILE"
) || {
  echo ""
  echo "GATEKEEPER: Deployment BLOCKED — action was denied or cancelled." >&2
  exit 1
}

# Save token for audit trail
echo "$TOKEN_JSON" > "$TOKEN_OUT"
echo "GATEKEEPER: Approved. Token saved to $TOKEN_OUT"

# ── Verify token immediately (defence-in-depth) ───────────────────────────────

VERIFY_RESULT=$(
  "$BINARY" verify "$TOKEN_OUT" "$PAYLOAD_FILE"
)
echo "GATEKEEPER verify: $VERIFY_RESULT"

if [[ "$VERIFY_RESULT" != VERIFIED* ]]; then
  echo "GATEKEEPER: Token verification failed — aborting deployment." >&2
  exit 1
fi

echo ""
echo "=== GATEKEEPER: Gate passed. Proceeding with deployment. ==="
echo ""

# ── The deployment command runs OUTSIDE this script ───────────────────────────
# The workflow step that calls this script exits 0 here.
# The NEXT workflow step runs the actual deploy:
#
#   vercel deploy --prebuilt --prod --token=${{ secrets.VERCEL_TOKEN }}
#
# Keeping the gate and the deploy in separate steps means:
#   • The deploy step is skipped automatically if this step fails.
#   • The token JSON is available as an artifact for the audit trail.
#   • The Vercel build cache (from vercel build --prod) is reused.

APPROVER=$(echo "$TOKEN_JSON" | python3 -c \
  "import sys,json; t=json.load(sys.stdin); print(t['approver_pubkey'][:16]+'...')" \
  2>/dev/null || echo "unknown")

echo "Authorised by approver pubkey: $APPROVER"
echo "Token file:                    $TOKEN_OUT"
