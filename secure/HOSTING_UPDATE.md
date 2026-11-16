# Updating the live secure shell (`BLITZ_RELEASE_BASELINE=shell`)

Use this when a production secure shell is already live on `master-intelligence-5496f-lb` and a newer, reviewed shell commit has to replace it. The original Step C run used the `demo` baseline, which can no longer pass: the fictional demo is gone and `/data.enc.json` now returns 404.

R2: the `demo` baseline has been **removed** from `deploy-secure-blitz.sh`. It authenticated only the demo's `data.enc.json` digest, so unapproved demo `index.html`/`app.js`/CSS beside the pinned ciphertext passed as a rollback target. `BLITZ_RELEASE_BASELINE` has no default: unset, `demo`, or any value other than `shell` stops the run before any test or cloud call, and so does `BLITZ_EXPECTED_DEMO_RELEASE`. `secure-release.mjs --version-files-demo` now always fails.

**Separate owner approval is required for every run.** It must name the exact commit and the exact live release. Nothing in this document is an approval.

## What the script enforces in shell mode

Before anything is deployed:

- One-shot opt-in, approved commit equals `HEAD`, clean tree, not CI, and no passphrase in the environment.
- `BLITZ_RELEASE_BASELINE=shell` (required, no default) together with `BLITZ_EXPECTED_LIVE_RELEASE`. Setting `BLITZ_EXPECTED_DEMO_RELEASE` is refused.
- `hosting:blitz` mapping, hosting-only config, billing `False`, and the exact site listed.
- `npm test`, `verify:bundle`, and `test:secure` with a fresh 7/7 iPhone attestation. Approval variables are kept out of the test processes.
- A production build from the untracked web config, verified as 15 files with no ciphertext, then **frozen once** into a private release root under `TMPDIR` (outside the repository): read-only copies of the 15 files plus a SHA-256 manifest. Its digest is printed as `STEP_C_RELEASE_MANIFEST_SHA256`. Nothing after this reads `.firebase-blitz-private-shell`.
- The live channel's current release equals `BLITZ_EXPECTED_LIVE_RELEASE`.
- The live site is an exact production secure shell. Every one of the 15 shell paths and `/` answers **200 with no redirect**, with exactly one of each header in `firebase.secure-blitz.json` at its exact value (CSP equal to the production policy, `X-Frame-Options: DENY`, `Cache-Control: no-store`, …) and no report-only CSP. The page carries the exact production meta CSP and loads only `config.js` and `shell.js`; `config.js` is the production web config; `/data.enc.json` returns 404.
- R2: an **approved release record** is required: `BLITZ_APPROVED_BASELINE_RECORD` (a file holding the `STEP_C_RELEASE_RECORD` line printed by the verified deploy that produced the live shell, plus a newline) and `BLITZ_APPROVED_BASELINE_RECORD_SHA256` (that run's `STEP_C_RELEASE_RECORD_SHA256`, recorded in the owner's approval). The live version must be the record's version, every served byte must equal the record's SHA-256, and the rollback version's Hosting content hashes must equal the record's. A shell that only *looks* right (correct headers, page and config but a different `shell.js`) is refused. The digest must come from the approval packet, never from the live site.
- The live version that the rollback would restore lists **exactly** the 15 shell files in the Hosting API, with the approved content, so a rollback cannot republish anything else.
- The frozen release still matches its manifest.
- A second read of the live channel immediately before deploying. Any change stops the run.

The deploy is one `firebase deploy --config <release root>/firebase.json --only hosting:blitz --project master-intelligence-5496f --non-interactive --json`; `--json` makes the CLI report the one version it created (`STEP_C_DEPLOYED_VERSION`). That config is the approved `firebase.secure-blitz.json` with `public` pointed at the frozen copy.

After the deploy:

- The release changed, `/` returns 200, `/data.enc.json` returns 404, and billing is `False`.
- The frozen release still matches its manifest (nothing changed it during the upload).
- R1: the live channel serves exactly the version the CLI reported, not just some version with the same file names.
- R1: that version lists exactly the manifest's files **and** each file's Hosting content hash equals the frozen file's. The Hosting API does not report SHA-256 of the bytes: firebase-tools 14.22.0 names each file by SHA-256 of its gzip stream at level 9, so the verifier recomputes that from the frozen copy (proven equal to the CLI's own `Uploader` in `tests/secure-release.test.mjs`). The verifier must run under the same Node/zlib as the CLI; a different zlib fails closed (stop and rollback), never open.
- Every manifest file and `/` is **byte-identical** to the manifest and passes the same status, redirect, header, CSP and script checks as the baseline.
- R1: the live channel is read once more after every check; if it changed while being verified, the run stops.

Any failure after the deploy prints `STEP_C_ROLLBACK_COMMAND` and stops. It never retries.

## Operator run (Cloud Shell, one run)

```bash
git rev-parse HEAD            # must equal the approved commit
git status --porcelain        # must be empty
# Read-only: copy release.name from the channel resource.
TOKEN="$(gcloud auth print-access-token)"
curl --fail --silent --show-error --max-time 20 --retry 0 \
  -H "Authorization: Bearer ${TOKEN}" \
  "https://firebasehosting.googleapis.com/v1beta1/sites/master-intelligence-5496f-lb/channels/live"
unset TOKEN

unset DASHBOARD_PASSPHRASE CI GITHUB_ACTIONS BLITZ_EXPECTED_DEMO_RELEASE
export BLITZ_RELEASE_BASELINE=shell
export BLITZ_APPROVED_COMMIT=<approved full SHA>
export BLITZ_EXPECTED_LIVE_RELEASE='<release.name from the read above>'
# R2: the approved record of the live shell, and its approved digest.
printf '%s\n' '<STEP_C_RELEASE_RECORD JSON from the run that deployed the live shell>' > <private>/baseline-record.json
export BLITZ_APPROVED_BASELINE_RECORD=<private>/baseline-record.json
export BLITZ_APPROVED_BASELINE_RECORD_SHA256=<STEP_C_RELEASE_RECORD_SHA256 from the approval packet>
BLITZ_APPROVE_SECURE_SHELL_DEPLOY=YES bash scripts/deploy-secure-blitz.sh
```

Record `STEP_C_LIVE_RELEASE`, `STEP_C_NEW_RELEASE`, `STEP_C_DEPLOYED_VERSION`, `STEP_C_RELEASE_MANIFEST_SHA256`, `STEP_C_RELEASE_RECORD`, `STEP_C_RELEASE_RECORD_SHA256` and `STEP_C_ROLLBACK_COMMAND`. The record and its digest are what the next update's approval must name as its baseline.

A shell that is already live but was deployed before release records existed has no record. It cannot be used as a shell baseline until a record for it is produced from its reviewed commit's frozen build and its live version, and that record's digest is independently approved. This change does not provide or approve such a record. Do not post tokens, UIDs or emails.

## Rollback

Run the printed command once:

```bash
firebase hosting:clone --project master-intelligence-5496f --non-interactive master-intelligence-5496f-lb@<PREVIOUS_VERSION_ID> master-intelligence-5496f-lb:live
```

This re-releases the previous **shell** version on the same site and channel. It touches no Firestore data, rules, Auth or claims.

Restore check:

1. The channel's `release.version.name` is `sites/master-intelligence-5496f-lb/versions/<PREVIOUS_VERSION_ID>`.
2. `/` returns 200 and `/data.enc.json` returns 404.
3. Billing is `False`.

Then stop.
