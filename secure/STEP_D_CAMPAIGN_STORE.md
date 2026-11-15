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
| Target | `--target production` needs project `master-intelligence-5496f` exactly. It refuses CI, emulator variables, `GOOGLE_APPLICATION_CREDENTIALS` and `FIREBASE_TOKEN`, so it runs only with the operator's existing gcloud session. `--target emulator` needs a `demo-` project on loopback and `@example.com` accounts. |
| Input | Must be a strict envelope (7 fields, v1, 600,000 iterations, strict base64, under 1 MB) stored **outside this repository**. Anything sharing a salt, IV or ciphertext with the public `docs/data.enc.json` is refused. |
| Dry run | The default. It prints `requiredExpectCurrent` and `requiredApproval`. |
| `--apply` | Needs `BLITZ_STORE_UID` = `BLITZ_STORE_CONFIRM_UID` (from the environment, never argv). Needs `BLITZ_STORE_APPROVAL` = `WRITE:<input digest>` or `RETRACT:<current digest>`, and `--expect-current <digest or none>`. |
| Owner | A write needs the UID to be enabled, email-verified, Google-linked and holding a strict `blitzOwner: true`, so D0 must be done first. Retract works without the claim. |
| Concurrency | `--expect-current` is checked again inside a Firestore transaction. Any change in between stops the run with no write. |
| Backup | When a document already exists, `--backup <file>` is required. The file must be outside the repo and not already exist. It is written with mode 600 and verified by digest **before** any mutation. |
| Verify | Reads the document back afterwards and compares digests. Prints the exact rollback. |

## Producing the envelope (owner, private machine)

Use the **rotated** passphrase, not the one exposed on Oct 31. Write the envelope outside the repo so the GitHub Pages bundle is not changed:

```bash
BLITZ_DIR=<private campaign source folder> BLITZ_OUTPUT_DIR=<private folder outside the repo> \
  DASHBOARD_PASSPHRASE='<rotated passphrase>' node scripts/build.mjs
unset DASHBOARD_PASSPHRASE
```

## Production run (Cloud Shell, after approval)

```bash
unset DASHBOARD_PASSPHRASE CI GITHUB_ACTIONS GOOGLE_APPLICATION_CREDENTIALS FIREBASE_TOKEN \
      FIRESTORE_EMULATOR_HOST FIREBASE_AUTH_EMULATOR_HOST
# Admin SDK with user credentials needs the quota project. This changes no IAM.
gcloud auth application-default login
gcloud auth application-default set-quota-project master-intelligence-5496f

export BLITZ_STORE_UID='<privately verified owner UID>'
P='--target production --project master-intelligence-5496f'

node scripts/blitz-campaign-store.mjs inspect $P
node scripts/blitz-campaign-store.mjs write $P --input <private>/data.enc.json     # dry run; read the digests

export BLITZ_STORE_CONFIRM_UID='<the same UID, typed again>'
export BLITZ_STORE_APPROVAL='WRITE:<inputDigest from the dry run>'
node scripts/blitz-campaign-store.mjs write $P --input <private>/data.enc.json \
  --expect-current none --apply                                                   # add --backup <file> when a document exists
unset BLITZ_STORE_UID BLITZ_STORE_CONFIRM_UID BLITZ_STORE_APPROVAL
```

Then sign in on the secure shell with the owner's Google account, unlock with the rotated passphrase, and check the campaign against its source counts. Record only digests and pass/fail.

## Rollback

The successful output includes a `rollback` object:

- **First write** (no prior document): `retract` with `--expect-current <liveDigest>`, approval `RETRACT:<liveDigest>`, and a `--backup` file.
- **Replacement**: `write --input <backup file>` with `--expect-current <liveDigest>` and approval `WRITE:<previousDigest>`.
- **Retract**: `write --input <backup file> --expect-current none`.

Retracting removes the document from Firestore. It cannot recall copies a signed-in browser already decrypted. Revoking the owner (D0 rollback) is separate and is documented in `D0_OWNER_ACCESS.md`.

## Tests

- `npm test`: unit tests with in-memory Firestore/Auth fakes. They cover refusals, CAS, backup verification, round-trips, and the CLI refusing before the SDK loads.
- `npm run test:store`: Auth and Firestore emulators with the secure-shell rules. The Admin SDK writes; the browser's own `readPrivateDocument` reads and decrypts. It requires exactly 3/3.
