# Secure production migration for LinkedIn Blitz

**Design only. Not implemented. Not approved to build, deploy, or enable services.**

This document describes a later move of the real November campaign off public Hosting ciphertext and onto Firebase Authentication plus deny-by-default Firestore. It does not authorize that move. The fictional demo (`firebase.json`, `.firebase-blitz-demo`, `scripts/deploy-firebase-demo.sh`) stays a separate path and must never carry real contacts.

`smg980/meeting-prep-dashboard` was not readable with the credential available while this note was written (GitHub returned not found). The shape below follows that project's described split, as already recorded in [FIREBASE_BLITZ_MIGRATION.md](FIREBASE_BLITZ_MIGRATION.md): a `firebase.secure.json` that is not the demo config, Firestore rules that fail closed, and a rollout note that keeps the current public site up until acceptance. The secure files are **quoted here**. They are intentionally not added as repo files in this change, so nothing can deploy them by accident.

## What stays separate

| Path | Contents | Who can deploy it |
| --- | --- | --- |
| GitHub Pages `docs/` | Live November campaign, including `docs/data.enc.json` | Existing Pages publish from `main`. Unchanged until acceptance. |
| `firebase.json` + `scripts/deploy-firebase-demo.sh` | Four fictional contacts only | Guarded script, `hosting:blitz` only, after a separate synthetic approval. |
| Future `firebase.secure.json` + rules | App shell with no campaign file, plus private rules | Not in this repo yet. Requires its own approval, emulator proof, and a merged ruleset. |

Do not point the secure config at `docs/` or at `.firebase-blitz-demo`. Do not copy `docs/data.enc.json` into Hosting, into a public URL, or into a world-readable Firestore document.

## Access model

Use the existing project `master-intelligence-5496f` and the dedicated site `master-intelligence-5496f-lb`. Do not create a second Firebase project. Do not change Meeting Prep's `prep` target, the default site, or `master-intelligence-5496f-app`.

Authentication:

- Google sign-in only.
- Require `request.auth.token.email_verified == true`.
- Allow only an owner allowlist. The allowed email and uid are supplied at rules-deploy time from a gitignored file. Do not commit them.
- Reject every other Google account, an unverified email, a signed-out client, and a stale token.
- Do not enable phone auth, anonymous auth, or email-link auth. Phone authentication is a billing-prone path and is out of scope.

Data:

- One Firestore document per owner uid, for example `blitzOwners/{uid}/campaign/current`.
- The document holds the client-side AES-256-GCM payload (the same envelope style the dashboard already uses: PBKDF2-SHA256, random salt and IV). The passphrase is not stored in Firestore, Hosting, or git.
- Hosting serves an app shell only: HTML, CSS, JS, fonts, and images. The shell's file list is an explicit allowlist with **zero** `data.enc.json`, source CSV, draft export, or credential file.
- After sign-in, the client reads that one document and decrypts it locally. A failed auth check or a failed decrypt shows the lock screen and no contacts.
- Rules deny all writes from clients. Loading or rotating the payload is a later, separately approved admin action, not a browser upload.

Contacts, account names, role and relationship notes, signals, and outreach drafts (connection notes and follow-ups) stay inside that encrypted document. The Hosting shell may show them only after decrypt. The shell must not embed them, send them to a third party, or write them to `localStorage`. Session storage of the passphrase, if kept at all, remains tab-scoped and clears on Lock, matching the current dashboard.

## Proposed rules

These rules are a proposal, not a file named `firestore.rules`.

```
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /{document=**} {
      allow read, write: if false;
    }
    match /blitzOwners/{uid}/campaign/current {
      allow read: if request.auth != null
        && request.auth.uid == uid
        && request.auth.token.email_verified == true
        && request.auth.token.email == "OWNER_EMAIL_FROM_GITIGNORED_FILE";
      allow write: if false;
    }
  }
}
```

**Do not deploy that block by itself.** Firestore rules for this project are one ruleset. Publishing a Blitz-only file would replace Meeting Prep and any MASTER rules. Before any rules change:

1. An approved operator reads the current live ruleset. That read is not part of this design change.
2. The Blitz `match` is added beside the existing matches. The deny-all `{document=**}` block must not shadow an existing allow. Put specific allows so they are not overridden by a later blanket deny, and test the merged file.
3. The merged rules run in the Firestore emulator: owner read allowed; other uid denied; unauthenticated denied; unverified email denied; list/collection queries denied; all writes denied; Meeting Prep's existing cases still pass.
4. Only then, under a separate approval, deploy **the merged ruleset**. Never deploy rules from `scripts/deploy-firebase-demo.sh`.

## Proposed secure Hosting config

Also not added as a file. A future `firebase.secure.json` would look like this and would be selected only with an explicit `--config firebase.secure.json` after approval:

```json
{
  "firestore": { "rules": "firestore.rules" },
  "hosting": {
    "target": "blitz",
    "public": ".firebase-blitz-private-shell",
    "ignore": ["firebase.json", "**/.*", "**/node_modules/**"]
  }
}
```

The private shell directory is a future allowlisted build. It must refuse `DASHBOARD_PASSPHRASE` inherited from a production shell unless the operator is on the approved private-build path, and it must refuse to copy `docs/data.enc.json`. The synthetic deploy script does not reference `firebase.secure.json` and must stay that way.

`firebase.json` remains the fictional-demo config: hosting target `blitz` only, public directory `.firebase-blitz-demo`.

## Spark plan and cost

Keep the project on the Spark plan. Do not link a billing account, do not upgrade to Blaze, and do not enable Cloud Functions, Cloud Run, or phone auth.

This design uses Hosting, Google sign-in, and one Firestore document. Recheck the current Spark quotas in the Firebase console before any service is turned on. Published Spark quotas change; do not treat a number in this note as a spending limit. On Spark, going past a quota stops that product instead of charging. That is the intended cost control. If Google reports that a required API now needs Blaze, stop and ask Steven. Do not enable billing to get past the warning.

A single owner document and a small static shell are the expected load. The November campaign must not be given to a public CDN as ciphertext "to save Firestore reads." Public ciphertext is the current Pages risk and is not the Firebase end state.

## Keep GitHub Pages until acceptance

`https://smg980.github.io/linkedin-blitz-dashboard/` remains the campaign the operator can use. Do not redirect it, do not delete `docs/data.enc.json`, and do not change `blitz.masterintelligence.ai` DNS while the private path is unproven. DNS, if ever used, is a separate approval after the signed-in site passes.

## Migration, verification, and rollback

Migration, after synthetic Hosting is already accepted and after a new written approval:

1. Enable Google sign-in for the project only if it is not already on. Do not disable Meeting Prep's provider settings. Stop if the console asks to upgrade billing.
2. Build the private shell and confirm its file list has no campaign payload.
3. Encrypt the November campaign with a new passphrase that has not been committed or logged. A passphrase that may have been exposed earlier is not reused. Do not print the plaintext or the passphrase.
4. Write the ciphertext to `blitzOwners/{ownerUid}/campaign/current` with an admin action that is not a Hosting upload. Client rules still deny writes.
5. Deploy the **shell** with an explicit config and `--only hosting:blitz --project master-intelligence-5496f --non-interactive`. Deploy merged rules only under the rules approval from the previous section. These are two separate approvals.
6. Verify, signed in as the owner: four real sections render only after unlock, Lock clears them, and a second Google account sees no document. Signed-out and unverified sessions see no document. `curl` of the Hosting origin returns no `data.enc.json`. The Pages hash is unchanged. Meeting Prep and the other Hosting sites still load.
7. Leave Pages in place. Retire it only after Steven accepts the signed-in site in writing.

Rollback:

- Pages is already the fallback. Do nothing to `docs/`.
- Disable only the Blitz site: `firebase hosting:disable --project master-intelligence-5496f --site master-intelligence-5496f-lb --force`.
- Stop reads by deploying the previous merged ruleset (the one from before the Blitz match), which was saved before the rules change. Do not deploy an empty rules file.
- Delete `blitzOwners/{uid}/campaign/current` only if Steven asks to remove the private copy. Deleting the Firestore doc does not delete Pages.
- Do not run `hosting:sites:delete` against any site except `master-intelligence-5496f-lb`, and only with a separate request. Do not delete the prep, app, or default site.

## Still blocked before any of this can start

- Synthetic site creation and the fictional deploy are their own approval. See [SYNTHETIC_HOSTING_RUNBOOK.md](SYNTHETIC_HOSTING_RUNBOOK.md).
- No live ruleset has been read, so a safe merge cannot be prepared yet.
- Google sign-in and Firestore are not turned on by this design.
- The owner allowlist email and uid are not in git.
- Passphrase rotation for the November campaign has not been done.
- DNS for `blitz.masterintelligence.ai` is not authorized.
