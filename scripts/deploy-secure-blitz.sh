#!/usr/bin/env bash
# Private secure-shell Hosting-only release; needs a separately reviewed pinned commit.
# No Firestore rules, Auth settings, campaign data, owner claims, DNS, or billing are changed here.
# The access token is written to a mode-600 file and is never printed.
#
# Read-only baseline is GET .../sites/$SITE/channels/live. That resource's release
# is the version currently served. A releases list is not used: its order is not
# documented, so pageSize=1 is not the live release.
# BLITZ_EXPECTED_LIVE_RELEASE must be that release.name, copied from a separate
# read-only GET of the same channel. It is not a short id and not a version id.
#
# BLITZ_RELEASE_BASELINE=shell is required: the live site must already be a
# production secure shell (data.enc.json 404, production config.js, shell
# markers). After the deploy every live file must be byte-identical to the
# frozen release manifest (F2 below).
# R2 (demo removed): the one-time Step C `demo` baseline is disabled. It
# authenticated only the demo's data.enc.json digest, so arbitrary demo
# index.html/app.js/CSS beside the pinned ciphertext passed as a rollback
# target. The demo is no longer live, so `demo`, an unset baseline and
# BLITZ_EXPECTED_DEMO_RELEASE are all refused before any cloud call.
# R2: shell also needs BLITZ_APPROVED_BASELINE_RECORD (a file holding the
# STEP_C_RELEASE_RECORD line a previous verified deploy printed, plus a
# newline) and BLITZ_APPROVED_BASELINE_RECORD_SHA256 (its independently
# approved STEP_C_RELEASE_RECORD_SHA256). The live version, its Hosting content
# hashes and every served byte must equal that record before anything deploys,
# so a shell that merely looks right (arbitrary shell.js) is not a baseline.
#
# F2: the reviewed build is frozen once into a private release root outside the
# repository (scripts/secure-release.mjs) with a SHA-256 manifest of every file.
# firebase deploy reads only that root. The manifest digest printed as
# STEP_C_RELEASE_MANIFEST_SHA256 binds the pre-deploy re-check, the post-deploy
# re-check, the live version's file list and every live byte.
# R1: `firebase deploy --json` reports the version it created; the live channel
# must serve exactly that version, its Hosting content hashes (SHA-256 of the
# CLI's level-9 gzip) must equal the frozen files', and the channel is re-read
# after all checks so drift during verification stops the run.
# F3: after the deploy every file must answer 200 with no redirect and with the
# exact approved CSP and security headers; the page must carry the exact CSP and
# load only config.js and shell.js. The rollback version must list exactly the
# approved baseline record's files and Hosting hashes. The shell baseline must
# itself pass the same exact header, status, CSP and script checks before
# anything is deployed over it.
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
release_url="https://firebasehosting.googleapis.com/v1beta1/sites/${SITE}/channels/live"

main_pid=$BASHPID
token_file=""
expected_release=""
deploy_started=0
deploy_verified=0
rollback_command=""
previous_release=""
previous_version=""
previous_version_id=""
captured=""
release_root=""
manifest_sha=""
fetch_dir=""
fetch_dirs=()

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
  local fetched
  for fetched in ${fetch_dirs[@]+"${fetch_dirs[@]}"}; do rm -rf "$fetched"; done
  if [[ -n "$release_root" ]]; then node scripts/secure-release.mjs --remove "$release_root" || rm -rf "$release_root"; fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM

[[ -z "${CI:-}" && -z "${GITHUB_ACTIONS:-}" ]] || stop 'Never deploy from CI.'
[[ "${BLITZ_APPROVE_SECURE_SHELL_DEPLOY:-}" == 'YES' ]] || stop 'Explicit Step C opt-in is required.'
[[ -z "${DASHBOARD_PASSPHRASE:-}" ]] || stop 'No campaign passphrase may be in the environment.'
# R2: only the shell baseline exists. There is no default.
RELEASE_BASELINE="${BLITZ_RELEASE_BASELINE:-}"
case "$RELEASE_BASELINE" in
  shell) ;;
  demo|'') stop 'The demo rollback baseline is disabled; set BLITZ_RELEASE_BASELINE=shell with an approved baseline record.' ;;
  *) stop 'BLITZ_RELEASE_BASELINE must be shell.' ;;
esac
[[ -z "${BLITZ_EXPECTED_DEMO_RELEASE:-}" ]] || stop 'BLITZ_EXPECTED_DEMO_RELEASE is no longer accepted; the shell baseline uses BLITZ_EXPECTED_LIVE_RELEASE.'
expected_release="${BLITZ_EXPECTED_LIVE_RELEASE:-}"
[[ -n "${BLITZ_APPROVED_COMMIT:-}" ]] || stop 'Pinned reviewed commit is required.'
[[ "$(git rev-parse HEAD)" == "$BLITZ_APPROVED_COMMIT" ]] || stop 'Checkout is not the approved commit.'
[[ -z "$(git status --porcelain)" ]] || stop 'Dirty checkout; preserve uncommitted work.'
[[ -n "$expected_release" ]] || stop 'The exact expected live release name is required.'
# R2: the live shell is a rollback target only if it is exactly an
# independently approved release record (bytes, Hosting hashes, version).
[[ -n "${BLITZ_APPROVED_BASELINE_RECORD:-}" && "${BLITZ_APPROVED_BASELINE_RECORD_SHA256:-}" =~ ^[0-9a-f]{64}$ ]] \
  || stop 'The shell baseline needs BLITZ_APPROVED_BASELINE_RECORD and its approved BLITZ_APPROVED_BASELINE_RECORD_SHA256.'
command -v firebase >/dev/null || stop 'Authorized Firebase CLI missing.'
command -v gcloud >/dev/null || stop 'Authorized gcloud missing.'
command -v curl >/dev/null || stop 'curl missing.'
command -v node >/dev/null || stop 'node missing.'
command -v sha256sum >/dev/null || stop 'sha256sum missing.'
[[ -f "${BLITZ_SECURE_CONFIG:-secure-config.local.json}" ]] || stop 'Untracked Firebase WEB config missing; do not create credentials.'

node scripts/secure-release.mjs --check-baseline-record "$BLITZ_APPROVED_BASELINE_RECORD" "$BLITZ_APPROVED_BASELINE_RECORD_SHA256" "$SITE" \
  || stop 'The approved baseline record is invalid or does not match its approved digest.'
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
    -u BLITZ_EXPECTED_LIVE_RELEASE \
    -u BLITZ_RELEASE_BASELINE \
    -u BLITZ_APPROVED_BASELINE_RECORD \
    -u BLITZ_APPROVED_BASELINE_RECORD_SHA256 \
    npm test || stop 'npm test failed.'
env -u BLITZ_APPROVE_SECURE_SHELL_DEPLOY \
    -u BLITZ_APPROVED_COMMIT \
    -u BLITZ_EXPECTED_DEMO_RELEASE \
    -u BLITZ_EXPECTED_LIVE_RELEASE \
    -u BLITZ_RELEASE_BASELINE \
    -u BLITZ_APPROVED_BASELINE_RECORD \
    -u BLITZ_APPROVED_BASELINE_RECORD_SHA256 \
    npm run verify:bundle || stop 'verify:bundle failed.'
BLITZ_SECURE_ATTEST_NONCE="$(node -e 'process.stdout.write(require("node:crypto").randomBytes(16).toString("hex"))')" || stop 'Cannot create the secure suite attestation.'
[[ "$BLITZ_SECURE_ATTEST_NONCE" =~ ^[0-9a-f]{32}$ ]] || stop 'Cannot create the secure suite attestation.'
BLITZ_SECURE_ATTEST_PATH="$(mktemp)" || stop 'Cannot create the secure suite attestation.'
rm -f "$BLITZ_SECURE_ATTEST_PATH"
export BLITZ_SECURE_ATTEST_NONCE BLITZ_SECURE_ATTEST_PATH
env -u BLITZ_APPROVE_SECURE_SHELL_DEPLOY \
    -u BLITZ_APPROVED_COMMIT \
    -u BLITZ_EXPECTED_DEMO_RELEASE \
    -u BLITZ_EXPECTED_LIVE_RELEASE \
    -u BLITZ_RELEASE_BASELINE \
    -u BLITZ_APPROVED_BASELINE_RECORD \
    -u BLITZ_APPROVED_BASELINE_RECORD_SHA256 \
    npm run test:secure || stop 'test:secure failed.'
require_suite_attestation || stop 'Secure suite attestation is missing or does not match this run.'
node scripts/build-secure-shell.mjs --config "${BLITZ_SECURE_CONFIG:-secure-config.local.json}" || stop 'Secure shell build failed.'
node scripts/secure-hosting-guard.mjs --assert-shell || stop 'Secure shell output check failed.'
[[ -z "$(git status --porcelain)" ]] || stop 'Build modified tracked files.'
[[ "$(git rev-parse HEAD)" == "$BLITZ_APPROVED_COMMIT" ]] || stop 'Checkout drift after tests.'
node scripts/secure-hosting-guard.mjs --assert-config || stop 'Private Hosting config check failed.'
node scripts/secure-hosting-guard.mjs --assert-shell || stop 'Secure shell output check failed.'
# F2: freeze the checked build once. Nothing below reads .firebase-blitz-private-shell.
frozen="$(node scripts/secure-release.mjs --freeze .firebase-blitz-private-shell)" || stop 'Could not freeze the reviewed build.'
release_root="$(printf '%s\n' "$frozen" | sed -n '1p')"
manifest_sha="$(printf '%s\n' "$frozen" | sed -n '2p')"
[[ -n "$release_root" && -d "$release_root" && "$manifest_sha" =~ ^[0-9a-f]{64}$ ]] || stop 'Could not freeze the reviewed build.'
node scripts/secure-release.mjs --verify-frozen "$release_root" "$manifest_sha" || stop 'Frozen release does not match its manifest.'
echo "STEP_C_RELEASE_MANIFEST_SHA256=${manifest_sha}"

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

# Sets fetch_dir in this shell (not a subshell) so cleanup sees every directory.
new_fetch_dir() {
  fetch_dir="$(mktemp -d)" || return 1
  fetch_dirs+=("$fetch_dir")
  chmod 700 "$fetch_dir" || return 1
}

version_files() {
  # The default page holds far more files than a shell release; a continuation
  # token is refused by the checker rather than followed.
  curl --fail --silent --show-error --max-time 20 --retry 0 \
    -H @"$token_file" \
    "https://firebasehosting.googleapis.com/v1beta1/sites/${SITE}/versions/$1/files"
}

fetch_with_headers() {
  # Records status and headers. A redirect is captured and refused, never followed.
  curl --silent --show-error --max-time 20 --retry 0 \
    -H 'Cache-Control: no-cache' -H 'Pragma: no-cache' \
    -D "$2.headers" -o "$2.body" "$1"
}

fetch_shell_paths() {
  # Fetches every secure-shell path and "/" with headers into $1, in allowlist order.
  local dir="$1" paths rel index=0
  paths="$(node scripts/secure-release.mjs --shell-paths)" || return 1
  while IFS= read -r rel; do
    [[ -n "$rel" ]] || continue
    fetch_with_headers "https://${SITE}.web.app/${rel}" "${dir}/${index}" || return 1
    index=$((index + 1))
  done <<< "$paths"
  fetch_with_headers "https://${SITE}.web.app/" "${dir}/root"
}

verify_shell_baseline() {
  local code
  new_fetch_dir || return 1
  fetch_shell_paths "$fetch_dir" || return 1
  node scripts/secure-release.mjs --verify-baseline-shell "$fetch_dir" || return 1
  node scripts/secure-release.mjs --verify-baseline-bytes "$BLITZ_APPROVED_BASELINE_RECORD" "$BLITZ_APPROVED_BASELINE_RECORD_SHA256" "$SITE" "$fetch_dir" || return 1
  code="$(http_code "https://${SITE}.web.app/data.enc.json")" || return 1
  [[ "$code" == '404' ]] || return 1
}

verify_live_release() {
  local dir paths rel index=0
  new_fetch_dir || return 1
  dir="$fetch_dir"
  paths="$(node scripts/secure-release.mjs --paths "$release_root" "$manifest_sha")" || return 1
  while IFS= read -r rel; do
    [[ -n "$rel" ]] || continue
    fetch_with_headers "https://${SITE}.web.app/${rel}" "${dir}/${index}" || return 1
    index=$((index + 1))
  done <<< "$paths"
  fetch_with_headers "https://${SITE}.web.app/" "${dir}/root" || return 1
  node scripts/secure-release.mjs --verify-live "$release_root" "$manifest_sha" "$dir"
}

http_code() {
  curl --silent --show-error --output /dev/null --write-out '%{http_code}' --max-time 20 --retry 0 \
    -H 'Cache-Control: no-cache' -H 'Pragma: no-cache' "$1"
}

capture_live || stop 'Could not capture exact live rollback release/version.'
previous="$captured"
previous_release="$(printf '%s\n' "$previous" | sed -n '1p')"
previous_version="$(printf '%s\n' "$previous" | sed -n '2p')"
previous_version_id="$(printf '%s\n' "$previous" | sed -n '3p')"
validate_release_fields "$previous_release" "$previous_version" "$previous_version_id" || stop 'Invalid rollback source.'
[[ "$expected_release" == "$previous_release" ]] || stop "Current live release does not equal the explicitly verified ${RELEASE_BASELINE} release. Captured: ${previous_release}"
node scripts/secure-release.mjs --check-baseline-record "$BLITZ_APPROVED_BASELINE_RECORD" "$BLITZ_APPROVED_BASELINE_RECORD_SHA256" "$SITE" "$previous_version" \
  || stop 'The live version is not the approved baseline version.'
verify_shell_baseline || stop 'Live Hosting content is not the approved production secure shell with no public ciphertext.'
require_billing_off 'Billing changed before deploy.' || stop 'Billing changed before deploy.'
capture_live || stop 'Could not re-read the live Hosting release.'
[[ "$captured" == "$previous" ]] || stop 'Concurrent Hosting change detected.'
require_suite_attestation || stop 'Secure suite attestation is missing or does not match this run.'
# F3: the rollback target must serve exactly its baseline's files and nothing else.
write_token
version_files "$previous_version_id" \
  | node scripts/secure-release.mjs --version-files-record "$BLITZ_APPROVED_BASELINE_RECORD" "$BLITZ_APPROVED_BASELINE_RECORD_SHA256" "$SITE" \
  || stop 'Rollback version is not exactly the approved secure shell baseline; it is not a trustworthy baseline.'
node scripts/secure-release.mjs --verify-frozen "$release_root" "$manifest_sha" || stop 'Frozen release changed before deploy.'

rollback_command="firebase hosting:clone --project ${PROJECT} --non-interactive ${SITE}@${previous_version_id} ${SITE}:live"
echo "STEP_C_BASELINE=${RELEASE_BASELINE}"
echo "STEP_C_LIVE_RELEASE=${previous_release}"
echo "STEP_C_LIVE_VERSION=${previous_version}"
echo "STEP_C_ROLLBACK_COMMAND=${rollback_command}"
echo "STEP_C: deploying one secure SHELL-ONLY release to hosting:${TARGET} in ${PROJECT}"
deploy_started=1
# R1: --json makes the CLI report the one version it created and released.
deploy_json="$(firebase deploy --config "${release_root}/firebase.json" --only "hosting:$TARGET" --project "$PROJECT" --non-interactive --json)" \
  || stop 'The Firebase CLI deploy failed.'
deployed_version="$(printf '%s' "$deploy_json" | node scripts/secure-release.mjs --deploy-version "$SITE")" \
  || stop 'The Firebase CLI did not report exactly one version on this site.'
echo "STEP_C_DEPLOYED_VERSION=${deployed_version}"

capture_live || stop 'Deploy returned but the new live Hosting release could not be read back.'
post_deploy="$captured"
[[ "$captured" != "$previous" ]] || stop 'Hosting release did not change after deployment.'
new_release="$(printf '%s\n' "$captured" | sed -n '1p')"
new_version="$(printf '%s\n' "$captured" | sed -n '2p')"
new_version_id="$(printf '%s\n' "$captured" | sed -n '3p')"
validate_release_fields "$new_release" "$new_version" "$new_version_id" || stop 'Post-deploy release was not an exact dedicated-site release.'
[[ "$new_version_id" != "$previous_version_id" ]] || stop 'Hosting version did not change after deployment.'
# R1: the live channel must serve the version this run uploaded, not merely
# a version with the same file names (another deploy could have landed).
[[ "$new_version" == "$deployed_version" ]] || stop 'The live channel does not serve the version this deploy uploaded.'
shell_code="$(http_code "https://${SITE}.web.app/")" || stop 'Could not read the private shell HTTP status.'
[[ "$shell_code" == '200' ]] || stop "Private shell did not return HTTP 200 (got ${shell_code})."
cipher_code="$(http_code "https://${SITE}.web.app/data.enc.json")" || stop 'Could not read the ciphertext path HTTP status.'
[[ "$cipher_code" == '404' ]] || stop "Public ciphertext path returned HTTP ${cipher_code}; immediate operator review required."
node scripts/secure-release.mjs --verify-frozen "$release_root" "$manifest_sha" || stop 'Frozen release changed during deploy.'
write_token
# R1: every file's content hash in the uploaded version (the CLI's gzip
# representation) must equal the frozen manifest's file, not just its path.
version_files "$new_version_id" | node scripts/secure-release.mjs --version-files "$release_root" "$manifest_sha" \
  || stop 'Live version files or content hashes are not exactly the frozen manifest.'
verify_live_release || stop 'Live files, status codes or security headers do not match the frozen release.'
require_billing_off 'Billing state changed.'
# R1: nothing may have replaced the verified release while it was checked.
capture_live || stop 'Could not re-read the live Hosting release after verification.'
[[ "$captured" == "$post_deploy" ]] || stop 'The live Hosting channel changed after verification.'
# R2: the record a later shell update needs as its approved rollback baseline.
record_out="$(node scripts/secure-release.mjs --release-record "$release_root" "$manifest_sha" "$deployed_version" "$SITE")" \
  || stop 'Could not produce the release record.'
release_record="$(printf '%s\n' "$record_out" | sed -n '1p')"
release_record_sha="$(printf '%s\n' "$record_out" | sed -n '2p')"
[[ -n "$release_record" && "$release_record_sha" =~ ^[0-9a-f]{64}$ ]] || stop 'Could not produce the release record.'
deploy_verified=1
echo "STEP_C_DEPLOY_VERIFIED: new release ${new_release}; manifest ${manifest_sha}; exact files, headers and CSP; public ciphertext 404; billing OFF."
echo "STEP_C_NEW_RELEASE=${new_release}"
echo "STEP_C_RELEASE_RECORD=${release_record}"
echo "STEP_C_RELEASE_RECORD_SHA256=${release_record_sha}"
echo "STEP_C_ROLLBACK_COMMAND=${rollback_command}"
