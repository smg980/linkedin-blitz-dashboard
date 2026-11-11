#!/usr/bin/env bash
# Proposed future synthetic-only Firebase release for LinkedIn Blitz.
# NEVER publish the real GitHub Pages campaign dataset with this script.
# This script cannot create a Hosting site, alter Firebase rules, or enable billing.
# Do not run it until the operator runbook is separately approved.
set -Eeuo pipefail
cd "$(dirname "$0")/.."

if [[ -n "${GITHUB_ACTIONS:-}" || -n "${CI:-}" ]]; then
  echo "STOP: synthetic Blitz deploy cannot run in CI." >&2
  exit 1
fi

PROJECT="master-intelligence-5496f"
SITE="master-intelligence-5496f-lb"
TARGET="blitz"

if [[ "${BLITZ_APPROVE_SYNTHETIC_DEPLOY:-}" != "YES" ]]; then
  echo "STOP: a separate explicit synthetic-only Blitz deployment approval is required." >&2
  exit 1
fi
if [[ -n "${DASHBOARD_PASSPHRASE:-}" ]]; then
  echo "STOP: production dashboard passphrase must not be present." >&2
  exit 1
fi
command -v firebase >/dev/null || {
  echo "STOP: authorized Firebase CLI is unavailable; do not install credentials." >&2
  exit 1
}

node scripts/blitz-hosting-guard.mjs --assert-config

# No private campaign decryption or real-data rebuild.
npm test
npm run verify:bundle
npm run build:firebase-demo
npm run verify:firebase-demo

# Re-read the mapping after the tests. Never create a site from here.
node scripts/blitz-hosting-guard.mjs --assert-config
echo "Checking that site $SITE already exists. This command does not create a site."
if ! firebase hosting:sites:list --project "$PROJECT" --json --non-interactive \
  | node scripts/blitz-hosting-guard.mjs --require-site "$SITE"; then
  echo "STOP: dedicated Blitz Hosting site is absent or cannot be verified." >&2
  exit 1
fi
node scripts/blitz-hosting-guard.mjs --assert-config

echo "Deploying synthetic-only Firebase project $PROJECT, Hosting target $TARGET, site $SITE."
firebase deploy --only "hosting:$TARGET" --project "$PROJECT" --non-interactive
