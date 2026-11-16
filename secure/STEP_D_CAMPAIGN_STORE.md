# Step D: loading the private campaign (`scripts/blitz-campaign-store.mjs`)

This tool writes, replaces or retracts the one owner document the secure shell reads: `blitzOwners/{uid}/campaign/current` in `master-intelligence-5496f`. It uses the Firebase Admin SDK. Client writes stay denied by the rules.

**Every production run needs its own owner approval.** The approval names the exact UID, the action and the envelope digest. Nothing here is an approval. The tool has only been run against emulators.

## What it does and does not touch

- **Ciphertext only.** The input is an AES-256-GCM/PBKDF2 envelope built beforehand with the existing `scripts/build.mjs`. The tool never reads a passphrase or plaintext, and it refuses to run if any `*PASSPHRASE*` variable is set.
- **One document.** No listing, no other paths, and no claims, rules, Auth, Hosting, IAM or billing.
- **Output.** Booleans and SHA-256 envelope digests only. UIDs, emails and claims never appear. Errors are fixed `STORE_REFUSED <code>` lines.

## Guards

| Guard | Rule |
| --- | --- |
| Target | `--target production` needs project `master-intelligence-5496f` exactly. It refuses CI, emulator variables, and any spelling of a credential override, present even if empty: `GOOGLE_APPLICATION_CREDENTIALS` / `google_application_credentials`, `FIREBASE_TOKEN`, `GOOGLE_OAUTH_ACCESS_TOKEN`, `CLOUDSDK_AUTH_ACCESS_TOKEN[_FILE]`, `CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE`. `--target emulator` needs a `demo-` project on loopback and `@example.com` accounts. |
| Credential (F4) | Production never uses generic Application Default Credentials (which can silently fall through to a key file or the metadata server). It reads only gcloud's user ADC file (`$CLOUDSDK_CONFIG` or `~/.config/gcloud`, `application_default_credentials.json`, written by `gcloud auth application-default login`): a regular file, not a symlink, owned by the operator, not group/other-writable, outside the repo, `type: authorized_user`, no impersonation or external-account fields, quota project `master-intelligence-5496f`. R3: the checked fields build one google-auth-library `UserRefreshClient` (resolved from firebase-admin's own dependency graph); Firestore receives it as `authClient` and Admin Auth receives a credential wrapping the same client. firebase-admin 13.5.0 cannot build Firestore from `admin.refreshToken(...)` (`firestore/invalid-credential`), so the Admin SDK's `getFirestore` is not used. Then the token's account must equal `gcloud config get-value account` (case-insensitive). Neither identity is printed; the output says only `operatorIdentityBound: true`. |
| Input | Must be a strict envelope (7 fields, v1, 600,000 iterations, strict base64, under 1 MB) stored **outside this repository**. Anything sharing a salt, IV or ciphertext with the public `docs/data.enc.json` is refused. |
| Dry run | The default. It prints `requiredExpectCurrent` and `requiredApproval`. |
| `--apply` | Needs `BLITZ_STORE_UID` = `BLITZ_STORE_CONFIRM_UID` (from the environment, never argv). Needs `BLITZ_STORE_APPROVAL` = `WRITE:<input digest>` or `RETRACT:<current digest>`, `--expect-current <digest or none>`, and `--receipt <new file>`. |
| Operator lock | Every `--apply` takes the per-project lock in `~/.blitz-operator/` (mode 700). It refuses with `STORE_OPERATOR_LOCK_HELD` while a D0 claim change or another store run holds it. A stale lock is never broken automatically. |
| Owner | A write needs the UID to be enabled, email-verified, Google-linked and holding a strict `blitzOwner: true`, so D0 must be done first. Retract works without the claim. |
| Claim race | Auth cannot join a Firestore transaction. For a write the owner record (claims, disabled, verified, providers, `tokensValidAfterTime`) is fingerprinted when planned and must be identical just before the transaction and again inside it; any change refuses with nothing written. It is read once more after the commit; a change there is reported (exit 4), never called verified. The operator lock keeps the D0 claim tools out for the whole run. |
| Concurrency | `--expect-current` is checked again inside a Firestore transaction run with `maxAttempts: 1`, so the SDK never re-runs an ambiguous commit. Any change in between stops the run with no write. |
| Backup | When a document already exists, `--backup <file>` is required. The file must be outside the repo and not already exist. It is written with mode 600, flushed, and verified by digest **before** any mutation. |
| Receipt (F6) | `--receipt <file>` (outside the repo, new, mode 600) is created and flushed before the backup and again before the commit. It records the action, a SHA-256 of the UID (never the UID), the expected and intended digests, the verified backup path and digest, and `rollbackIfCommitted`: the exact command inputs that undo this run. Its `status` ends as one of the outcomes below. |
| Paths (F5) | Input, backup, receipt, lock directory and ADC file are resolved to real paths and must be outside the repository by path segment (so `<repo>/..private/` is inside) and by file identity of every ancestor (bind mounts, other spellings). |
| Verify | Reads the document back afterwards and compares digests. Prints the exact rollback. |

## Outcomes and exit codes

| Exit | Receipt `status` | Meaning | What to do |
| --- | --- | --- | --- |
| 0 | `COMMITTED_VERIFIED` | Commit acknowledged and read back as intended. | Record digests. |
| 1 | `REFUSED_PRE_WRITE` (or no receipt yet) | Refused before the commit was sent: nothing changed. | Fix the cause; start again from a dry run. |
| 3 | `OUTCOME_UNKNOWN` | The commit was sent and its result is not known (lost acknowledgement, failed or mismatched readback). `observedDigest` is one read taken afterwards. | **Do not re-run the apply.** Run `inspect`. If the live digest is `intendedDigest`, it committed: use `rollbackIfCommitted` if it must be undone. If it is `expectCurrent`, it did not. Anything else is a concurrent writer: stop for review. |
| 4 | `COMMITTED_ELIGIBILITY_CHANGED` | Committed and read back, but the owner record changed during the commit. | Review the claim change; undo with `rollbackIfCommitted` if needed. |
| 5 | `READY_TO_COMMIT` (stale) | Committed and read back, but the final receipt update failed. | Treat as committed; the receipt still holds `rollbackIfCommitted`. |

Exit 1 prints `STORE_REFUSED <code>`. Exits 3, 4 and 5 print `STORE_UNRESOLVED <code>`: something may have changed.

## Producing the envelope (owner, private machine)

Use the **rotated** passphrase, not the one exposed on Oct 31. Use only the private export wrapper: `scripts/build.mjs` on its own writes into the public `docs/` folder whenever `BLITZ_OUTPUT_DIR` is missing. The wrapper refuses an output folder inside the repo, one that is not mode 700 and owned by you, an existing `data.enc.json`, a source inside the repo, a `BLITZ_OUTPUT_DIR` in the environment, and any build flag. It stops if `docs/data.enc.json` or `git status` changed, or if the build left anything but one strict envelope, and removes its staging folder either way. It prints only the envelope digest.

```bash
mkdir -m 700 <private folder outside the repo>
BLITZ_DIR=<private campaign source folder> DASHBOARD_PASSPHRASE='<rotated passphrase>' \
  node scripts/export-private-envelope.mjs --out <private folder outside the repo>
unset DASHBOARD_PASSPHRASE
```

## Production run (Cloud Shell, after approval)

```bash
unset DASHBOARD_PASSPHRASE CI GITHUB_ACTIONS GOOGLE_APPLICATION_CREDENTIALS google_application_credentials \
      FIREBASE_TOKEN GOOGLE_OAUTH_ACCESS_TOKEN CLOUDSDK_AUTH_ACCESS_TOKEN CLOUDSDK_AUTH_ACCESS_TOKEN_FILE \
      CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE FIRESTORE_EMULATOR_HOST FIREBASE_AUTH_EMULATOR_HOST
# The user ADC file for the same account gcloud is signed in as. This changes no IAM.
gcloud auth application-default login
gcloud auth application-default set-quota-project master-intelligence-5496f
# The tool refuses unless the ADC account equals this active account.
gcloud config get-value account   # check privately; do not paste it anywhere

export BLITZ_STORE_UID='<privately verified owner UID>'
P='--target production --project master-intelligence-5496f'

node scripts/blitz-campaign-store.mjs inspect $P
node scripts/blitz-campaign-store.mjs write $P --input <private>/data.enc.json     # dry run; read the digests

export BLITZ_STORE_CONFIRM_UID='<the same UID, typed again>'
export BLITZ_STORE_APPROVAL='WRITE:<inputDigest from the dry run>'
node scripts/blitz-campaign-store.mjs write $P --input <private>/data.enc.json \
  --expect-current none --receipt <private>/receipt-1.json --apply                # add --backup <file> when a document exists
unset BLITZ_STORE_UID BLITZ_STORE_CONFIRM_UID BLITZ_STORE_APPROVAL
```

Then sign in on the secure shell with the owner's Google account, unlock with the rotated passphrase, and check the campaign against its source counts. Record only digests and pass/fail.

## Rollback

The receipt's `rollbackIfCommitted` (also printed as `rollback` on success) is the undo, with every input it needs:

- **First write** (no prior document): `retract` with `--expect-current <intendedDigest>`, approval `RETRACT:<intendedDigest>`, a new `--backup` file and a new `--receipt`.
- **Replacement**: `write --input <recorded backup path>` (its digest is recorded as `inputDigest`) with `--expect-current <intendedDigest>`, approval `WRITE:<previousDigest>`, a new `--backup` and a new `--receipt`.
- **Retract**: `write --input <recorded backup path> --expect-current none`, approval `WRITE:<previousDigest>`, and a new `--receipt`.

Each undo is itself a governed run: dry run first, then `--apply`. Never re-run an apply that ended `OUTCOME_UNKNOWN`; inspect first.

Retracting removes the document from Firestore. It cannot recall copies a signed-in browser already decrypted. Revoking the owner (D0 rollback) is separate and is documented in `D0_OWNER_ACCESS.md`.

## Tests

- `npm test`: unit tests with in-memory Firestore/Auth fakes. They cover refusals, CAS, backup verification, round-trips, and the CLI refusing before the SDK loads; plus `campaign-store-recovery.test.mjs` (receipts, lost acknowledgement, failed readback, concurrent update, backup failure, replacement rollback, claim race, path boundaries), `operator-controls.test.mjs` (credential provenance, identity binding, operator lock) and `export-private-envelope.test.mjs`; `operator-clients.test.mjs` runs production mode through `main()` with the real pinned SDK clients against a local TLS Firestore (gRPC) and Identity Toolkit, synthetic credentials and an in-memory token transport.
- `npm run test:store`: Auth and Firestore emulators with the secure-shell rules. The Admin SDK writes; the browser's own `readPrivateDocument` reads and decrypts. It requires exactly 3/3.
