# D0 owner access preparation — no production activation

This milestone prepares and rehearses owner provisioning. It grants no real
access. PR #16 stays draft, unmerged and pinned at
`1efcd89ad5bb43d3db0944a383cd600954b8a51e`. Production Hosting release
`1794426642121000` is the supplied baseline; this task does not deploy or verify
it through a production mutation. Do not run the Step C deployment wrapper for D0.

## Existing contract and scope

The client uses Google authentication, refreshes its token on sign-in and performs
only a GET of `blitzOwners/{authenticated UID}/campaign/current`. The rules contract
requires a Google sign-in token, verified email, matching path UID and boolean
`blitzOwner: true`; listing, queries and all client writes are denied. A linked
Google provider alone is insufficient: the current sign-in token must be Google.
Email is identity evidence, never an authorization allowlist.

This repository has an emulator-only rules fixture in
`scripts/run-secure-suite.mjs`, not the deployed merged ruleset. The live rules
are maintained elsewhere. No production Auth configuration or live rules were
read or changed for this preparation. Before activation an authorized operator
must privately verify the live merged rules enforce this exact contract. Stop on
any mismatch; rules/Auth changes need a separate approval and are outside D0.
Do not change MASTER, Meeting Prep, Pages, IAM, DNS, billing or infrastructure.

## Browser prerequisite: reuse an installed binary

Use the existing GitHub Actions workflow (Node 22, Java 21) or an authorized local
development environment. Prefer an installed Chrome/Chromium. This task's Linux
development environment has `/usr/bin/chromium` (Chromium 156.0.8078.79) and Java
21.0.13; the full seven-test run verified Puppeteer compatibility. Local Node was
24.22.1; Node 22 in CI is the supported reproducibility target. No Firebase cloud
service, billing change, or new browser framework is needed.

From the development branch with a clean environment and no production credentials:

```bash
npm ci
node --version
java -version
export CHROME_PATH=/usr/bin/chromium
"$CHROME_PATH" --version
node --input-type=module -e 'import {findChrome} from "./scripts/secure-browser-check.mjs"; console.log(await findChrome());'
npm test
npm run verify:bundle
npm run verify:firebase-demo
BLITZ_SECURE_ARTIFACTS="$PWD/screenshots/d0" npm run test:secure
npm run verify:secure-shell
```

On a Mac with Chrome already installed, use instead:

```bash
export CHROME_PATH='/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
```

The Mac path is supported by the existing preflight; this task did not access or
test the user's Mac. The CI step now calls that same preflight before installing
anything; it retains the existing Chrome fallback only when discovery fails.
An explicit invalid `CHROME_PATH` must fail, not silently fall back. First-time
`npm ci` and emulator runs require package registry and Google emulator download
access. Subsequent runs can reuse their caches.

The runner requires a real Chrome/Chromium `--version` banner, seven passing
integration tests, zero skips/cancellations and a passing iPhone test before
writing its per-run attestation. Its watchdog, signal cleanup and deployment
guards are unchanged. The browser test uses a 390×844 touch viewport and iPhone
Safari user agent, including redirect sign-in. It is Chromium emulation, not a
physical iPhone/Safari engine test. Do not skip it or fake an attestation.

In the managed environment, sandboxed Node subprocess probes returned `EPERM`
despite Chromium printing its version. Running the normal test commands through
the environment's approved outer executor resolved this; the preflight was not
weakened. Browser artifacts belong under ignored `screenshots/` or a writable
temporary directory, never the old environment-specific `/opt/cursor/artifacts`.

## Read-only identification of the intended real account (future operator step)

1. Use the existing authorized Firebase Console session for project
   `master-intelligence-5496f`, Authentication → Users. Do not create credentials,
   enable a provider, invite a user or export the user list. Turn off recording,
   shell tracing, log capture and screenshots containing identities.
2. Have the owner privately identify the intended Google account. Match its
   verified email and Google provider in the Console, then obtain the exact
   Firebase UID. Do not substitute a Google subject ID or infer UID from email.
   If no account exists, stop: any sign-in/account-creation step needs separate
   authorization. This preparation does not create a production account.
3. Privately cross-check the UID against the owner's authenticated Firebase
   session. Do not copy ID/refresh tokens into chat, logs or GitHub. A decoded
   token alone is not trusted identity verification.
4. Using an already authorized Admin SDK session with an explicitly selected
   project, call only `getUser(exactUid)` to confirm UID, enabled state,
   `emailVerified === true`, Google provider and existing claims. Inspect in a
   private session; never print the UserRecord. Confirm there is no unexpected
   tenant; this procedure targets the default project Auth instance only.
5. Audit existing `blitzOwner` assignments privately, with paginated read-only
   `listUsers` only if necessary to establish uniqueness. Produce only a count
   and pass/fail, never a user export or account list. An unexpected holder,
   wrong-type claim, identity ambiguity or inaccessible audit blocks activation;
   do not silently remove anyone's claims.

No real account lookup was executed in this milestone. Do not put real UID/email
in a command argument, environment dump, PR, issue, test fixture or log. Keep any
necessary operator notes in a private location outside the checkout; `.d0-private/`
is ignored as defense in depth, not a secret store. Do not download service account
keys. Do not add secrets to Actions.

## Repeatable synthetic rehearsal

`scripts/d0-owner-emulator.mjs` deliberately has no production mode. It requires
`FIREBASE_AUTH_EMULATOR_HOST` to be loopback, a `demo-` project, an exact UID and
an `@example.com` account. It refuses credential/passphrase environment variables.
It neither creates accounts nor reads Firestore. The integration suite creates
fictional Google accounts and exercises the same Admin SDK path used by this tool.

With an existing local Auth emulator and a fictional fixture UID (never a real UID):

```bash
export FIREBASE_AUTH_EMULATOR_HOST=127.0.0.1:9099
export BLITZ_D0_PROJECT=demo-blitz-secure
export BLITZ_D0_SYNTHETIC_UID=synthetic-owner
node scripts/d0-owner-emulator.mjs                 # read-only inspection
node scripts/d0-owner-emulator.mjs --grant         # dry-run; no writes
export BLITZ_D0_CONFIRM_UID=synthetic-owner
export BLITZ_D0_APPROVAL=APPLY_SYNTHETIC_ONLY
node scripts/d0-owner-emulator.mjs --grant --apply  # local fixture only
node scripts/d0-owner-emulator.mjs --revoke         # dry-run
node scripts/d0-owner-emulator.mjs --revoke --apply # remove claim, revoke refresh tokens
unset BLITZ_D0_CONFIRM_UID BLITZ_D0_APPROVAL BLITZ_D0_SYNTHETIC_UID
```

Use the emulator-generated fixture UID if it differs from this illustrative one.
No fixture account is automatically created by these commands; missing accounts
fail closed. `npm run test:secure` is the automated, self-contained rehearsal.
Outputs contain booleans only. Errors are generic so SDK responses cannot leak
identities. A failure after a write may mean partial completion; inspect privately
before retrying, never interpret a nonzero exit as proof that nothing changed.

## D0 activation checkpoint — future, separately approved

These steps are a gated operator runbook, not commands executed by this PR.
The rehearsal CLI cannot be pointed at production. A future authorized operator
must use the existing approved Admin SDK session; no automated production entry
point is added here.

1. Record the reviewed D0 commit, completed CI and independent review. Reconfirm
   PR #16 and Hosting baseline independently. Stop if the branch/rules/config
   drifted. Review this plan and explicitly approve **only** claim assignment and
   the agreed revocation action for one privately confirmed exact Firebase UID in
   `master-intelligence-5496f`. No email-only approval or wildcard UID is sufficient.
2. Complete the read-only identity, tenant, uniqueness and live-rule checks above.
   Keep a private in-memory snapshot of existing claims; do not serialize it to
   git or logs. Confirm the owner understands that no campaign will be ingested
   by D0 and that a missing private document can still show "not authorized."
3. Dry-run: compute `{ ...existingClaims, blitzOwner: true }` in memory. Compare
   the requested UID to the privately approved UID byte-for-byte; require a second
   explicit exact-UID confirmation immediately before mutation. Confirm project,
   operation, eligibility and preservation of all unrelated claims. Never accept
   an approval inherited from CI or the earlier Step C deployment approval.
4. With one operator and no concurrent custom-claim writers, re-read that exact
   account and compare its UID, identity attributes and complete claims against
   the approved snapshot. Abort on drift. The Admin SDK replaces the whole claim
   map and offers no compare-and-swap; the re-read alone cannot prevent races.
   Only then call `setCustomUserClaims(exactUid, mergedClaims)` once. No other UID,
   Firestore path, provider setting or service is modified.
5. Read back only that exact account. Verify strict boolean `blitzOwner === true`
   and deep equality of all unrelated claims. Have the owner sign out and sign
   back in with Google (or explicitly force token refresh); privately verify a
   trusted fresh ID token's UID, project/audience, Google sign-in provider,
   verified email and boolean owner claim. Never log the token or full payload.
6. Confirm the uniqueness audit remains unchanged except for that approved UID.
   A nonowner remains denied; a claim holder cannot read a different UID's path;
   signed-out, list/query and client writes remain denied. Use the existing
   synthetic emulator proof, plus an approved live synthetic canary only if one
   already exists and its access check is explicitly authorized. Do not create a
   document or grant a second real claim just to test. A missing document is not
   evidence that authorization succeeded. Keep real campaign ingestion gated.
7. Record only commit SHA, counts, time and pass/fail in the public checkpoint.
   Keep the exact UID and private approval in the private operator record. Stop
   before D/E/F, campaign ingestion, Hosting or rules deployment.

## Revocation, risks and rollback

Before any activation, obtain separate explicit approval for its exact-UID
revocation/rollback procedure (or an explicit contingency authorization covering
revocation after a failed assignment). Revocation affects this user's sessions
across Firebase applications in the project, potentially including Meeting Prep.
Do not disable/delete the account or remove unrelated custom claims.

For the privately confirmed UID, dry-run a copy of current claims with only
`blitzOwner` deleted. Re-read and compare the current account/claims under the same
single-writer discipline; require exact UID confirmation and explicit approval.
Call `setCustomUserClaims(uid, remainingClaims)`, then `revokeRefreshTokens(uid)`.
Read back to verify the owner key is absent, unrelated claims are unchanged and
`tokensValidAfterTime` advanced to the revocation operation. Sign out/clear the
owner's UI and test a fresh Google session/token: strict owner claim absent and
document GET denied. Repeat the read-only uniqueness audit; never auto-regrant.
An interrupted/failed revoke requires private inspection and completion of any
missing step, not restoration of the owner claim.

**Revocation is not immediate for issued ID tokens.** These unchanged Firestore
rules evaluate token claims; they do not consult Auth's refresh-token revocation
timestamp. An existing token with `blitzOwner: true` can retain GET access until
its normal expiry (typically up to one hour), even after refresh-token revocation.
The emulator regression proves both fresh-token denial and old-token acceptance.
Already downloaded ciphertext/plaintext cannot be recalled. If immediate server
denial is required, stop activation and obtain a separate reviewed change; do
not silently modify rules, delete data, or disable Hosting for this milestone.

D0 rollback is claim removal plus refresh-token revocation, not a Hosting rollback.
This task leaves release `1794426642121000` untouched. No Hosting action is part
of this checklist; any future Hosting rollback needs its own approval and an exact
captured version, never a broad deploy. Do not follow older migration rollback
instructions as authorization to disable this site or redeploy shared rules.

## Actions requiring new owner approval

- The exact production UID, project, boolean claim assignment, and private
  identity confirmation; production remains dry-run until that approval.
- Exact-UID revocation and cross-application refresh-token invalidation, including
  whether rollback after a failed activation is pre-authorized.
- Any production canary/data write, real campaign ingestion, rule/Auth change,
  Hosting deployment/rollback, merge, or later D/E/F work. None is authorized here.

Implementation and verification results are recorded in the draft PR with the
exact tested commit SHA; a queued CI run is never a passing result.
