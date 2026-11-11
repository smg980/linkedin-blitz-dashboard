#!/usr/bin/env bash
# Proposed future synthetic-only Firebase release for LinkedIn Blitz.
# NEVER publish the real GitHub Pages campaign dataset with this script.
# This script cannot create a Hosting site, alter any Firebase rules, or enable billing.
set -Eeuo pipefail
cd "$(dirname "$0")/.."

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

node --input-type=module <<'NODE'
import assert from 'node:assert/strict';
import fs from 'node:fs';
const project = 'master-intelligence-5496f';
const site = 'master-intelligence-5496f-lb';
const rc = JSON.parse(fs.readFileSync('.firebaserc', 'utf8'));
const config = JSON.parse(fs.readFileSync('firebase.json', 'utf8'));
assert.equal(rc.projects.default, project);
assert.deepEqual(rc.targets?.[project]?.hosting, { blitz: [site] });
assert.deepEqual(Object.keys(config), ['hosting']);
assert.equal(config.hosting?.target, 'blitz');
assert.equal(config.hosting?.public, '.firebase-blitz-demo');
assert.equal(config.hosting?.rewrites, undefined);
assert.equal(config.firestore, undefined);
console.log('PASS: release targets only the isolated LinkedIn Blitz Hosting site.');
NODE

# No private campaign decryption or real-data rebuild.
npm test
npm run verify:bundle
npm run build:firebase-demo
npm run verify:firebase-demo

# The dedicated site is NOT yet created; require separately approved creation.
# Never let firebase deploy offer to create a new site interactively.
if ! firebase hosting:sites:list --project "$PROJECT" | grep -Fq "$SITE"; then
  echo "STOP: dedicated Blitz Hosting site is absent or cannot be verified." >&2
  exit 1
fi

echo "Deploying synthetic-only Firebase project $PROJECT, Hosting target $TARGET, site $SITE."
firebase deploy --only "hosting:$TARGET" --project "$PROJECT" --non-interactive
