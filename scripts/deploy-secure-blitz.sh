#!/usr/bin/env bash
# Private secure-shell Hosting-only release; needs a separately reviewed pinned commit.
# No Firestore rules, Auth settings, campaign data, owner claims, DNS, or billing are changed here.
# The access token is written to a mode-600 file and is never printed.
#
# Read-only baseline is GET .../sites/$SITE/channels/live. That resource's release
# is the version currently served. A releases list is not used: its order is not
# documented, so pageSize=1 is not the live release.
# BLITZ_EXPECTED_DEMO_RELEASE must be that release.name, copied from a separate
# read-only GET of the same channel. It is not a short id and not a version id.
#
# This script never runs a rollback. If the deploy starts and verification does
# not pass, it prints STEP_C_ROLLBACK_COMMAND. That command re-releases only the
# captured version on this site's live channel. It is not hosting:disable, and
# it does not target the default site, -app, or -prep.
set -Eeuo pipefail
cd "$(dirname "$0")/.."

PROJECT="master-intelligence-5496f"
SITE="master-intelligence-5496f-lb"
TARGET="blitz"
DEMO_SHA="cf657dfeadc74bc5091f1dce72f68ba83754677234760c3182920ff088fccccd"
release_url="https://firebasehosting.googleapis.com/v1beta1/sites/${SITE}/channels/live"

main_pid=$BASHPID
token_file=""
deploy_started=0
deploy_verified=0
rollback_command=""
previous_release=""
previous_version=""
previous_version_id=""
captured=""

stop() { echo "STOP: $*" >&2; exit 1; }
require_suite_attestation() {
  [[ -n "${BLITZ_SECURE_ATTEST_NONCE:-}" && -n "${BLITZ_SECURE_ATTEST_PATH:-}" ]] || return 1
  [[ "$BLITZ_SECURE_ATTEST_NONCE" =~ ^[0-9a-f]{32}$ ]] || return 1
  [[ -f "$BLITZ_SECURE_ATTEST_PATH" ]] || return 1
  grep -F -x -q -- "nonce=${BLITZ_SECURE_ATTEST_NONCE}" "$BLITZ_SECURE_ATTEST_PATH" || return 1
  grep -F -x -q -- 'tests=7' "$BLITZ_SECURE_ATTEST_PATH" || return 1
  grep -F -x -q -- 'pass=7' "$BLITZ_SECURE_ATTEST_PATH" || return 1
  grep -F -x -q -- 'fail=0' "$BLITZ_SECURE_ATTEST_PATH" || return 1
  grep -F -x -q -- 'cancelled=0' "$BLITZ_SECURE_ATTEST_PATH" || return 1
  grep -F -x -q -- 'skipped=0' "$BLITZ_SECURE_ATTEST_PATH" || return 1
  grep -F -x -q -- 'todo=0' "$BLITZ_SECURE_ATTEST_PATH" || return 1
  grep -F -x -q -- 'iphone=pass' "$BLITZ_SECURE_ATTEST_PATH" || return 1
}
require_billing_off() {
  local state
  state="$(gcloud billing projects describe "$PROJECT" --format='value(billingEnabled)')" || stop "$1"
  [[ "$state" == 'False' ]] || stop "$1"
}
cleanup() {
  # Command substitutions are subshells and inherit this trap. Only the
  # original shell may delete the token or report a failed deploy.
  [[ "$BASHPID" == "$main_pid" ]] || return 0
  if [[ -n "$token_file" ]]; then rm -f "$token_file"; fi
  if [[ "$deploy_started" == 1 && "$deploy_verified" != 1 && -n "$rollback_command" ]]; then
    echo "STOP: the Hosting deploy was started and verification did not pass." >&2
    echo "Do not retry the deploy and do not deploy any other target." >&2
    echo "STEP_C_ROLLBACK_COMMAND=${rollback_command}" >&2
  fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM

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
command -v sha256sum >/dev/null || stop 'sha256sum missing.'
[[ -f "${BLITZ_SECURE_CONFIG:-secure-config.local.json}" ]] || stop 'Untracked Firebase WEB config missing; do not create credentials.'

node scripts/secure-hosting-guard.mjs --assert-config || stop 'Private Hosting config check failed.'
require_billing_off 'Billing is not verified OFF.' || stop 'Billing is not verified OFF.'
if ! firebase hosting:sites:list --project "$PROJECT" --json --non-interactive \
    | node scripts/secure-hosting-guard.mjs --require-site; then
  stop 'Site list verification failed.'
fi

# Stop on the failing check itself. set -e must not be the only gate.
env -u BLITZ_APPROVE_SECURE_SHELL_DEPLOY \
    -u BLITZ_APPROVED_COMMIT \
    -u BLITZ_EXPECTED_DEMO_RELEASE \
    npm test || stop 'npm test failed.'
env -u BLITZ_APPROVE_SECURE_SHELL_DEPLOY \
    -u BLITZ_APPROVED_COMMIT \
    -u BLITZ_EXPECTED_DEMO_RELEASE \
    npm run verify:bundle || stop 'verify:bundle failed.'
BLITZ_SECURE_ATTEST_NONCE="$(node -e 'process.stdout.write(require("node:crypto").randomBytes(16).toString("hex"))')" || stop 'Cannot create the secure suite attestation.'
[[ "$BLITZ_SECURE_ATTEST_NONCE" =~ ^[0-9a-f]{32}$ ]] || stop 'Cannot create the secure suite attestation.'
BLITZ_SECURE_ATTEST_PATH="$(mktemp)" || stop 'Cannot create the secure suite attestation.'
rm -f "$BLITZ_SECURE_ATTEST_PATH"
export BLITZ_SECURE_ATTEST_NONCE BLITZ_SECURE_ATTEST_PATH
env -u BLITZ_APPROVE_SECURE_SHELL_DEPLOY \
    -u BLITZ_APPROVED_COMMIT \
    -u BLITZ_EXPECTED_DEMO_RELEASE \
    npm run test:secure || stop 'test:secure failed.'
require_suite_attestation || stop 'Secure suite attestation is missing or does not match this run.'
node scripts/build-secure-shell.mjs --config "${BLITZ_SECURE_CONFIG:-secure-config.local.json}" || stop 'Secure shell build failed.'
node scripts/secure-hosting-guard.mjs --assert-shell || stop 'Secure shell output check failed.'
[[ -z "$(git status --porcelain)" ]] || stop 'Build modified tracked files.'
[[ "$(git rev-parse HEAD)" == "$BLITZ_APPROVED_COMMIT" ]] || stop 'Checkout drift after tests.'
node scripts/secure-hosting-guard.mjs --assert-config || stop 'Private Hosting config check failed.'
node scripts/secure-hosting-guard.mjs --assert-shell || stop 'Secure shell output check failed.'

write_token() {
  if [[ -z "$token_file" ]]; then
    token_file="$(mktemp)"
    chmod 600 "$token_file"
  fi
  local token
  token="$(gcloud auth print-access-token)" || stop 'Cannot get existing Cloud Shell access token.'
  [[ "$token" =~ ^[A-Za-z0-9._~+/=-]+$ ]] || stop 'Refusing an unexpected access-token shape.'
  [[ ${#token} -ge 20 && ${#token} -le 4096 ]] || stop 'Refusing an unexpected access-token shape.'
  printf 'Authorization: Bearer %s\n' "$token" > "$token_file"
  chmod 600 "$token_file"
}

read_release() {
  # Do not add --location. A redirect must fail closed rather than be followed.
  curl --fail --silent --show-error --max-time 20 --retry 0 \
    -H @"$token_file" \
    "$release_url" \
    | node scripts/secure-hosting-guard.mjs --release
}

capture_live() {
  write_token
  local raw count
  raw="$(read_release)" || return 1
  count="$(printf '%s\n' "$raw" | wc -l | tr -d '[:space:]')"
  [[ "$count" == '3' ]] || return 1
  captured="$raw"
}

validate_release_fields() {
  local release="$1" version="$2" version_id="$3"
  [[ "$release" =~ ^sites/${SITE}/(channels/live/)?releases/[A-Za-z0-9_-]{1,128}$ ]] || return 1
  [[ "$version_id" =~ ^[A-Za-z0-9_-]{1,128}$ ]] || return 1
  [[ "$version" == "sites/${SITE}/versions/${version_id}" ]] || return 1
}

verify_demo_sha() {
  local demo_sha
  demo_sha="$(curl --fail --silent --show-error --max-time 20 --retry 0 \
    -H 'Cache-Control: no-cache' -H 'Pragma: no-cache' \
    "https://${SITE}.web.app/data.enc.json" | sha256sum | cut -d' ' -f1)" || stop 'Cannot verify existing fictional demo.'
  [[ "$demo_sha" == "$DEMO_SHA" ]] || stop 'Live Hosting content is not the approved fictional demo.'
}

http_code() {
  curl --silent --show-error --output /dev/null --write-out '%{http_code}' --max-time 20 --retry 0 \
    -H 'Cache-Control: no-cache' -H 'Pragma: no-cache' "$1"
}

capture_live || stop 'Could not capture exact live demo rollback release/version.'
previous="$captured"
previous_release="$(printf '%s\n' "$previous" | sed -n '1p')"
previous_version="$(printf '%s\n' "$previous" | sed -n '2p')"
previous_version_id="$(printf '%s\n' "$previous" | sed -n '3p')"
validate_release_fields "$previous_release" "$previous_version" "$previous_version_id" || stop 'Invalid rollback source.'
[[ "${BLITZ_EXPECTED_DEMO_RELEASE:-}" == "$previous_release" ]] || stop "Current live release does not equal the explicitly verified fictional-demo release. Captured: ${previous_release}"
verify_demo_sha || stop 'Cannot verify existing fictional demo.'
require_billing_off 'Billing changed before deploy.' || stop 'Billing changed before deploy.'
capture_live || stop 'Could not re-read the live Hosting release.'
[[ "$captured" == "$previous" ]] || stop 'Concurrent Hosting change detected.'
require_suite_attestation || stop 'Secure suite attestation is missing or does not match this run.'

rollback_command="firebase hosting:clone --project ${PROJECT} --non-interactive ${SITE}@${previous_version_id} ${SITE}:live"
echo "STEP_C_LIVE_RELEASE=${previous_release}"
echo "STEP_C_LIVE_VERSION=${previous_version}"
echo "STEP_C_ROLLBACK_COMMAND=${rollback_command}"
echo "STEP_C: deploying one secure SHELL-ONLY release to hosting:${TARGET} in ${PROJECT}"
deploy_started=1
firebase deploy --config firebase.secure-blitz.json --only "hosting:$TARGET" --project "$PROJECT" --non-interactive

capture_live || stop 'Deploy returned but the new live Hosting release could not be read back.'
[[ "$captured" != "$previous" ]] || stop 'Hosting release did not change after deployment.'
new_release="$(printf '%s\n' "$captured" | sed -n '1p')"
new_version="$(printf '%s\n' "$captured" | sed -n '2p')"
new_version_id="$(printf '%s\n' "$captured" | sed -n '3p')"
validate_release_fields "$new_release" "$new_version" "$new_version_id" || stop 'Post-deploy release was not an exact dedicated-site release.'
[[ "$new_version_id" != "$previous_version_id" ]] || stop 'Hosting version did not change after deployment.'
shell_code="$(http_code "https://${SITE}.web.app/")" || stop 'Could not read the private shell HTTP status.'
[[ "$shell_code" == '200' ]] || stop "Private shell did not return HTTP 200 (got ${shell_code})."
cipher_code="$(http_code "https://${SITE}.web.app/data.enc.json")" || stop 'Could not read the ciphertext path HTTP status.'
[[ "$cipher_code" == '404' ]] || stop "Public ciphertext path returned HTTP ${cipher_code}; immediate operator review required."
require_billing_off 'Billing state changed.'
deploy_verified=1
echo "STEP_C_DEPLOY_VERIFIED: new release ${new_release}; shell HTTP 200; public ciphertext 404; billing OFF."
echo "STEP_C_NEW_RELEASE=${new_release}"
echo "STEP_C_ROLLBACK_COMMAND=${rollback_command}"
