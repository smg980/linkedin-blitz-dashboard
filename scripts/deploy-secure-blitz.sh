#!/usr/bin/env bash
# Private secure-shell Hosting-only release; needs a separately reviewed pinned commit.
# No Firestore rules, Auth settings, campaign data, or owner claims are changed here.
set -Eeuo pipefail
cd "$(dirname "$0")/.."

PROJECT="master-intelligence-5496f"
SITE="master-intelligence-5496f-lb"
TARGET="blitz"

stop() { echo "STOP: $*" >&2; exit 1; }
[[ -z "${CI:-}" && -z "${GITHUB_ACTIONS:-}" ]] || stop 'Never deploy from CI.'
[[ "${BLITZ_APPROVE_SECURE_SHELL_DEPLOY:-}" == 'YES' ]] || stop 'Explicit Step C opt-in is required.'
[[ -z "${DASHBOARD_PASSPHRASE:-}" ]] || stop 'No campaign passphrase may be in the environment.'
[[ -n "${BLITZ_APPROVED_COMMIT:-}" ]] || stop 'Pinned reviewed commit is required.'
[[ "$(git rev-parse HEAD)" == "$BLITZ_APPROVED_COMMIT" ]] || stop 'Checkout is not the approved commit.'
[[ -z "$(git status --porcelain)" ]] || stop 'Dirty checkout; preserve uncommitted work.'
command -v firebase >/dev/null || stop 'Authorized Firebase CLI missing.'
command -v gcloud >/dev/null || stop 'Authorized gcloud missing.'
command -v curl >/dev/null || stop 'curl missing.'
command -v node >/dev/null || stop 'node missing.'
[[ -f "${BLITZ_SECURE_CONFIG:-secure-config.local.json}" ]] || stop 'Untracked Firebase WEB config missing; do not create credentials.'

node scripts/secure-hosting-guard.mjs --assert-config
[[ "$(gcloud billing projects describe "$PROJECT" --format='value(billingEnabled)')" == 'False' ]] || stop 'Billing is not verified OFF.'
if ! firebase hosting:sites:list --project "$PROJECT" --json --non-interactive \
    | node scripts/secure-hosting-guard.mjs --require-site; then
  stop 'Site list verification failed.'
fi

npm test
npm run verify:bundle
npm run test:secure
node scripts/build-secure-shell.mjs --config "${BLITZ_SECURE_CONFIG:-secure-config.local.json}"
node scripts/secure-hosting-guard.mjs --assert-shell
[[ -z "$(git status --porcelain)" ]] || stop 'Build modified tracked files.'
[[ "$(git rev-parse HEAD)" == "$BLITZ_APPROVED_COMMIT" ]] || stop 'Checkout drift after tests.'
node scripts/secure-hosting-guard.mjs --assert-config

# Read-only REST endpoint: capture current live demo version for an exact rollback.
# The token is never printed, stored, or committed. This endpoint is site-scoped.
token="$(gcloud auth print-access-token)" || stop 'Cannot get existing Cloud Shell access token.'
[[ -n "$token" ]] || stop 'No authenticated token.'
release_url="https://firebasehosting.googleapis.com/v1beta1/sites/$SITE/channels/live/releases?pageSize=1"
read_release() {
  curl --fail --silent --show-error --max-time 20 \
    -H "Authorization: Bearer $token" "$release_url" \
      | node scripts/secure-hosting-guard.mjs --release
}
previous="$(read_release)" || stop 'Could not capture exact live demo rollback release/version.'
previous_release="$(printf '%s\n' "$previous" | sed -n '1p')"
previous_version="$(printf '%s\n' "$previous" | sed -n '2p')"
[[ -n "$previous_release" && -n "$previous_version" ]] || stop 'Invalid rollback source.'

# Require the expected former fictional-demo release, not a release from another rollout.
[[ "${BLITZ_EXPECTED_DEMO_RELEASE:-}" == "$previous_release" ]] || stop 'Current live release does not equal the explicitly verified fictional-demo release.'
echo "Previous demo version for controlled rollback: $previous_version"
# Confirm the existing site is still the exact known four-contact fictional demo.
demo_sha="$(curl --fail --silent --show-error --max-time 20 "https://$SITE.web.app/data.enc.json" | sha256sum | cut -d' ' -f1)" || stop 'Cannot verify existing fictional demo.'
[[ "$demo_sha" == 'cf657dfeadc74bc5091f1dce72f68ba83754677234760c3182920ff088fccccd' ]] || stop 'Live Hosting content is not the approved fictional demo.'

# Recheck the remote release just before publication to avoid overwriting concurrent work.
[[ "$(read_release)" == "$previous" ]] || stop 'Concurrent Hosting change detected.'
[[ "$(gcloud billing projects describe "$PROJECT" --format='value(billingEnabled)')" == 'False' ]] || stop 'Billing changed before deploy.'
node scripts/secure-hosting-guard.mjs --assert-config
node scripts/secure-hosting-guard.mjs --assert-shell

echo "STEP_C: deploying one secure SHELL-ONLY release to hosting:$TARGET in $PROJECT"
firebase deploy --config firebase.secure-blitz.json --only "hosting:$TARGET" --project "$PROJECT" --non-interactive

new_release="$(read_release)" || stop 'Deploy returned but the new live Hosting release could not be read back.'
[[ "$new_release" != "$previous" ]] || stop 'Hosting release did not change after deployment.'
[[ "$(curl --silent --output /dev/null --write-out '%{http_code}' --max-time 20 "https://$SITE.web.app/")" == '200' ]] || stop 'Private shell did not return HTTP 200.'
[[ "$(curl --silent --output /dev/null --write-out '%{http_code}' --max-time 20 "https://$SITE.web.app/data.enc.json")" == '404' ]] || stop 'Public ciphertext path still accessible; immediate operator review required.'
[[ "$(gcloud billing projects describe "$PROJECT" --format='value(billingEnabled)')" == 'False' ]] || stop 'Billing state changed.'
echo "STEP_C_DEPLOY_VERIFIED: new release and shell HTTP 200; public ciphertext 404; billing OFF."
echo "STEP_C_ROLLBACK_SOURCE=$previous_version"
# Do not auto-retry or auto-deploy a rollback on an ambiguous response.
