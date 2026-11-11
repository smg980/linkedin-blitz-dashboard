# LinkedIn Blitz → Firebase alongside Meeting Prep

**Status: engineering staging only; not deployed.** Date: November 9, 2026. Operator commands were written on November 11, 2026 and are still not authorized to run.
The existing GitHub Pages production dashboard stays live with its current encrypted November campaign until private-access acceptance.

The exact site-create, target, deploy, live-check, and rollback commands are in [SYNTHETIC_HOSTING_RUNBOOK.md](SYNTHETIC_HOSTING_RUNBOOK.md). Do not run them from this document. The private November-campaign design is [SECURE_PRODUCTION_MIGRATION.md](SECURE_PRODUCTION_MIGRATION.md). It is design only and is separate from the fictional demo.

## Intended topology

| Application | Firebase project | Hosting target | Hosting site ID | Planned custom domain |
| --- | --- | --- | --- | --- |
| Meeting Prep | `master-intelligence-5496f` | `prep` | `master-intelligence-5496f-prep` | `prep.masterintelligence.ai` |
| LinkedIn Blitz | `master-intelligence-5496f` | `blitz` | **proposed** `master-intelligence-5496f-lb` | `blitz.masterintelligence.ai` |

Site ID `master-intelligence-5496f-blitz` would be **31 characters** and is invalid. The proposed `master-intelligence-5496f-lb` fits the 30-character Firebase limit. Its availability and creation have **not** been verified. The project identifier is shared; the sites, build outputs and deploy targets remain separate. Nothing touches MASTER marketing, app, or Meeting Prep's `prep` target.

## Stage 1 — ready for review: local synthetic-only Hosting preview

```bash
npm test
npm run build:firebase-demo
npm run verify:firebase-demo
# Optional local inspection, using an already authenticated and authorized Firebase CLI:
firebase emulators:start --only hosting:blitz --project master-intelligence-5496f
```

`firebase.json` references **only** `.firebase-blitz-demo` and target `blitz`. The builder copies an explicit allowlist of static app assets from `docs`, but **never** copies `docs/data.enc.json`. It then runs `scripts/build.mjs --example` using a hard-coded, public **synthetic-only** demonstration passphrase. The preview has four fictional contacts, marked `EXAMPLE` in encrypted payload and visible unlock screen. The output folder is Gitignored. The synthetic builder refuses an inherited `DASHBOARD_PASSPHRASE` variable so a real passphrase isn't accidentally used.

GitHub CI runs tests, verifies that the app is synthetic after decrypting with the demo key, confirms the production ciphertext wasn't copied, checks the deploy allowlist and validates the Hosting security headers. **Do not deploy any production campaign ciphertext from this branch.** No GitHub Actions deploy permissions or Firebase credentials are configured or required for tests.

### Reviewed future synthetic release path (code only)

The staging builder now copies an **explicit list of individual files** rather
than whole asset directories. The verifier independently enumerates all nested
files in the output and rejects anything outside that list, including a stray
file under `img/` or `fonts/`. A dedicated regression test checks this.

A separate `scripts/deploy-firebase-demo.sh` is prepared for a **future,
separately approved** fictional-data test release. It is **not** run by
GitHub Actions or on `npm test`, and it will fail unless all these gates pass:

- `BLITZ_APPROVE_SYNTHETIC_DEPLOY=YES` was deliberately set by the
  authorized operator for this one release; no real dashboard passphrase
  may be in the environment.
- The exact project/target mapping remains `master-intelligence-5496f`
  / `hosting:blitz` / `master-intelligence-5496f-lb`.
- Local synthetic tests, current committed ciphertext *format* checks,
  synthetic build, full recursive file allowlist, and fictional payload
  decryption checks succeed.
- The dedicated Blitz Hosting site **already exists**. This script does not
  create it or grant any access.
- The final CLI command is only
  `firebase deploy --only hosting:blitz --project master-intelligence-5496f --non-interactive`.

**No live site exists merely because the script is prepared.** Site creation,
domain configuration and any synthetic deployment remain a separate
owner-approved Cloud-side step. The real LinkedIn campaign stays solely
on GitHub Pages; its existing encrypted file is never part of this
synthetic Firebase staging directory.

### Firebase side effects not performed

- Did not create or delete a Firebase Hosting site, configure DNS, deploy to Firebase, or edit the MASTER or Meeting Prep site.
- Did not enable Firestore, Storage, billing, Cloud Run, Firestore rules, Authentication providers, or IAM.
- Did not rotate or copy the October 31 potentially exposed production passphrase.
- Did not migrate private contact data or expose any non-synthetic data to Firebase.

## Stage 2 — gated: private production deployment

Firebase Hosting alone publicly serves static files. A passphrase-protected `data.enc.json` on Hosting is **still publicly retrievable**, even if its contents are encrypted. Do **not** copy the real public GitHub Pages ciphertext into this Firebase demo build or treat a Hosting-only move as access control.

When Meeting Prep's chosen Spark/Firestore identity design is independently reviewed and explicitly approved, design a **private LinkedIn Blitz** data path reusing the approved Firebase Auth configuration but authorizing Blitz separately (per approved UID/document). Before real release:

1. Resolve Meeting Prep PRs #7/#9/#10 and choose one supported production path (the original Cloud Run proposal would require billing; the Spark/Firestore proposal has project-wide rules implications).
2. Obtain the live MASTER ruleset and validate **merged rules** using Firebase emulator tests. Do not overwrite an existing project ruleset or assume a deny rule overrides a permissive wildcard.
3. Ensure Firebase Auth requires the intended signed-in identity, verified email, and independent document authorization. Fail closed when auth or storage configuration is missing; no user-facing data fetch before authorization.
4. Build the production site from an allowlisted **app shell**, with **zero** real campaign files, ciphertext, source CSV, credentials, or secret values under the Hosting `public` directory. A private endpoint / Firestore rules must gate encrypted data reads; independent application-level encryption is optional defense in depth, never a substitute for access controls.
5. Rotate the potentially exposed passphrase before publishing new customer data; validate a real-data unlock in an approved, non-public test. Consider rotation of Meeting Prep too if a shared key was used, but do not presume that.
6. Create the dedicated Hosting site only after confirming its availability and permissions. Associate target `blitz` with the new site and configure `blitz.masterintelligence.ai` using the owner's authorized Cloudflare DNS workflow; do not change the existing `prep` site.
7. Validate no cross-app authorization leakage, regression cases (bad/missing token, other UID, stale session, unverified email, list/write denial, bad ciphertext), real contact grouping, freshness warnings and recorded action states.
8. Deploy **only `hosting:blitz`** after explicit release approval. Confirm both domains and the GitHub Pages fallback before any redirect or retirement.

**Rollback:** retain GitHub Pages at `https://smg980.github.io/linkedin-blitz-dashboard/` unchanged until the signed-in Firebase site has passed browser acceptance. Back out via Firebase Hosting version rollback if a separate deployment later fails. Do not delete the original encrypted campaign file to effect a rollback.

## Ownership and handoff

ChatGPT can prepare and test the isolated Firebase Hosting build in GitHub now. Morgan can coordinate later private-source encryption and deployment once the access-control design is approved. This is an engineering migration plan, **not authorization to enable project services, modify IAM, spend money, or expose live customer data**.

For current Firebase multi-site mechanics and target limits, see:
- https://firebase.google.com/docs/hosting/multisites
- https://firebase.google.com/docs/cli/targets
- https://firebase.google.com/docs/hosting/full-config
