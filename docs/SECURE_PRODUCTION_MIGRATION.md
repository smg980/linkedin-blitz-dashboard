# Secure production migration for LinkedIn Blitz

**Production move: not approved to deploy or to enable services.** A synthetic shell exists for local proof. This note does not authorize a production deploy.

This document describes a later move of the real November campaign off public Hosting ciphertext and onto Firebase Authentication plus deny-by-default Firestore. The fictional demo (`firebase.json`, `.firebase-blitz-demo`, `scripts/deploy-firebase-demo.sh`) stays a separate path and must never carry real contacts.

The hosting shell config in this repo is `firebase.secure-blitz.json`. It is hosting-only. Deployable Firestore rules are not in this repository.

## What stays separate

| Path | Contents | Who can deploy it |
| --- | --- | --- |
| GitHub Pages `docs/` | Live November campaign, including `docs/data.enc.json` | Existing Pages publish from `main`. Unchanged until acceptance. |
| `firebase.json` + `scripts/deploy-firebase-demo.sh` | Four fictional contacts only | Guarded script, `hosting:blitz` only, after a separate synthetic approval. |
| `firebase.secure-blitz.json` | App shell with no campaign file. No rules file. | Not deployed from this repo. A later hosting deploy needs its own approval. |

Do not point the secure config at `docs/` or at `.firebase-blitz-demo`. Do not copy `docs/data.enc.json` into Hosting, into a public URL, or into a world-readable Firestore document.

## Access model

Use the existing project `master-intelligence-5496f` and the dedicated site `master-intelligence-5496f-lb`. Do not create a second Firebase project. Do not change Meeting Prep's `prep` target, the default site, or `master-intelligence-5496f-app`.

Authentication and data, in plain language:

- Google sign-in only. Phone auth, anonymous auth, and email-link auth stay off.
- The client reads one document, `blitzOwners/{uid}/campaign/current`, and only that document. It does not list or query.
- That get is allowed only when the caller is signed in with the Google provider, the email is verified, the signed-in uid is the `{uid}` in the path, and the ID token carries the boolean custom claim `blitzOwner` set to true.
- A missing document or a permission denial shows not authorized. List, query, and every client write are denied.
- The document holds the client-side AES-256-GCM payload (PBKDF2-SHA256, random salt and IV). The passphrase is not stored in Firestore, Hosting, git, or browser storage.
- Hosting serves an app shell only: HTML, CSS, JS, fonts, and images. The shell's file list has zero campaign ciphertext, source CSV, draft export, or credential file.
- After sign-in the client force-refreshes the ID token once, reads that one document, and decrypts it locally.
- Loading or rotating the payload is a later, separately approved admin action, not a browser upload.

Contacts, account names, role and relationship notes, signals, and outreach drafts stay inside that encrypted document. The shell may show them only after decrypt. It must not embed them, send them, or write them to browser storage. Lock and sign-out clear the decrypted view.

## Document path decision

`blitzOwners/{uid}/campaign/current` is the document path. It is one get per unlock. The owner uid scopes the namespace, which matches the design recorded with the hosting-readiness work. A later per-owner document can be added beside `current` without widening who may read this one. The path stays separate from `meetingPrepPrivate`.

## Rules

This repository does not contain a deployable ruleset, and it must not grow one. An earlier email-equality draft was removed because copying it would allow a get without the owner claim and would allow a document query.

The only deployable rules are the merged ruleset maintained in the private Meeting Prep repo. They ship as one merged release after separate owner approval. A Blitz-only rules file must not be published, because it would replace Meeting Prep and any other rules in the project. Do not deploy rules from `scripts/deploy-firebase-demo.sh`. Before that merged release, an approved operator reads the live ruleset, folds this contract in beside the existing matches, and runs the merged file in the emulator: owner get allowed; a verified Google user without the claim denied; another uid denied; signed-out denied; list and query denied; writes denied; Meeting Prep's existing cases still pass.

## Secure Hosting config

`firebase.secure-blitz.json` is hosting-only: target `blitz`, public directory `.firebase-blitz-private-shell`. It does not name a rules file. Select it only with an explicit config flag after a separate hosting approval. This repository does not add a deploy command for that config.

The shell build refuses an inherited production passphrase and refuses to copy `docs/data.enc.json`. The synthetic deploy script does not reference `firebase.secure-blitz.json`.

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
4. Write that ciphertext to `blitzOwners/{ownerUid}/campaign/current` with an admin action that is not a Hosting upload. The client still cannot write. Set the boolean `blitzOwner` claim for that owner through an approved admin action. Do not commit the uid or the claim.
5. Deploy the **shell** with the hosting-only config and `--only hosting:blitz --project master-intelligence-5496f --non-interactive`. Deploy the merged rules only under the separate rules approval. These are two approvals.
6. Verify, signed in as the owner: the campaign renders only after unlock, Lock clears it, and a verified Google account without the claim sees not authorized. A claim holder cannot read another uid's document. Signed-out sessions see nothing. `curl` of the Hosting origin returns no `data.enc.json`. The Pages hash is unchanged. Meeting Prep and the other Hosting sites still load.
7. Leave Pages in place. Retire it only after Steven accepts the signed-in site in writing.

Rollback:

- Pages stays the fallback. Do nothing to `docs/`.
- Disable the Blitz hosting site `master-intelligence-5496f-lb`: `firebase hosting:disable --project master-intelligence-5496f --site master-intelligence-5496f-lb --force`.
- Re-release the prior merged ruleset from the private Meeting Prep repo, the baseline equivalent to `0d08498e`. Do not publish a Blitz-only file or an empty rules file.
- Remove the `blitzOwner` claim from the owner account.
- Delete `blitzOwners/{uid}/campaign/current` only if Steven asks to remove the private copy. Deleting that document does not delete Pages.
- Do not run `hosting:sites:delete` against any site except `master-intelligence-5496f-lb`, and only with a separate request. Do not delete the prep, app, or default site.

## Still blocked before any of this can start

- Synthetic site creation and the fictional deploy are their own approval. See [SYNTHETIC_HOSTING_RUNBOOK.md](SYNTHETIC_HOSTING_RUNBOOK.md).
- No live ruleset has been read, so the merged release cannot be prepared yet. This repo is not the source of that ruleset.
- Google sign-in and Firestore are not turned on by this note.
- The owner uid and the `blitzOwner` claim are not in git.
- Passphrase rotation for the November campaign has not been done.
- DNS for `blitz.masterintelligence.ai` is not authorized.
