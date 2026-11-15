# Updating the live secure shell (`BLITZ_RELEASE_BASELINE=shell`)

Use this when a production secure shell is already live on `master-intelligence-5496f-lb` and a newer, reviewed shell commit has to replace it. The original Step C run used the `demo` baseline, which can no longer pass: the fictional demo is gone and `/data.enc.json` now returns 404.

**Separate owner approval is required for every run.** It must name the exact commit and the exact live release. Nothing in this document is an approval.

## What the script enforces in shell mode

Before anything is deployed:

- One-shot opt-in, approved commit equals `HEAD`, clean tree, not CI, and no passphrase in the environment.
- `BLITZ_RELEASE_BASELINE=shell` together with `BLITZ_EXPECTED_LIVE_RELEASE`. Setting `BLITZ_EXPECTED_DEMO_RELEASE` as well is refused.
- `hosting:blitz` mapping, hosting-only config, billing `False`, and the exact site listed.
- `npm test`, `verify:bundle`, and `test:secure` with a fresh 7/7 iPhone attestation. Approval variables are kept out of the test processes.
- A production build from the untracked web config, verified as 15 files with no ciphertext.
- The live channel's current release equals `BLITZ_EXPECTED_LIVE_RELEASE`.
- The live site is a production secure shell: `/`, `/config.js` and `/shell.js` carry the shell markers, the production CSP and a production web config, and `/data.enc.json` returns 404.
- A second read of the live channel immediately before deploying. Any change stops the run.

The deploy is one `firebase deploy --config firebase.secure-blitz.json --only hosting:blitz --project master-intelligence-5496f --non-interactive`.

After the deploy:

- The release changed, `/` returns 200, `/data.enc.json` returns 404, and billing is `False`.
- The live `index.html`, `config.js` and `shell.js` are **byte-identical** to the local build of the approved commit.

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
BLITZ_APPROVE_SECURE_SHELL_DEPLOY=YES bash scripts/deploy-secure-blitz.sh
```

Record `STEP_C_LIVE_RELEASE`, `STEP_C_NEW_RELEASE` and `STEP_C_ROLLBACK_COMMAND`. Do not post tokens, UIDs or emails.

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
