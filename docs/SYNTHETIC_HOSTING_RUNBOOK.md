# Synthetic LinkedIn Blitz Hosting runbook

**Do not run these commands unless Steven has given a separate, explicit approval after reviewing them.** Nothing in this file creates a site, deploys, changes DNS, or alters IAM, Auth, Firestore, or billing. The steps below are the only later operator sequence. They were not executed when this document was added.

This runbook publishes **fictional demo files only** to a new Hosting site. It does not move the November campaign. GitHub Pages (`docs/`, including `docs/data.enc.json`) stays as it is.

Project: `master-intelligence-5496f`  
New site ID: `master-intelligence-5496f-lb`  
Target: `hosting:blitz`  
Sites that must keep working untouched: default `master-intelligence-5496f`, Meeting Prep `master-intelligence-5496f-prep`, and `master-intelligence-5496f-app`.

## Before any command

1. Use a trusted terminal where `firebase` is already logged in as a project owner. Do not install a new credential, and do not run this from GitHub Actions. The deploy script exits if `CI` or `GITHUB_ACTIONS` is set.
2. `unset DASHBOARD_PASSPHRASE`. The production passphrase must not be in the environment.
3. `git status` is clean, and `git rev-parse HEAD` is the approved SHA on `main` (or the approved release commit).
4. `npm test`, `npm run verify:bundle`, `npm run build:firebase-demo`, and `npm run verify:firebase-demo` already pass locally. The guarded script runs them again.

## (a) Create the site

Run this only if a read-only `firebase hosting:sites:list --project master-intelligence-5496f --json --non-interactive` does **not** already contain the resource `projects/master-intelligence-5496f/sites/master-intelligence-5496f-lb`.

```bash
firebase hosting:sites:create master-intelligence-5496f-lb --project master-intelligence-5496f --non-interactive
```

This creates an empty Hosting site. It does not upload files and does not attach a domain. If Firebase says the ID is taken or invalid, stop. Do not invent a different site ID. Site IDs are limited to 30 characters; `master-intelligence-5496f-lb` is the approved ID.

After creation, list sites again and confirm all four IDs are present: `master-intelligence-5496f`, `master-intelligence-5496f-prep`, `master-intelligence-5496f-app`, and `master-intelligence-5496f-lb`. Do not delete or disable any of the first three.

## (b) Apply the target only if the committed mapping is missing

`.firebaserc` already maps `blitz` to `master-intelligence-5496f-lb` and to no other site. Do not run `target:apply` when that mapping is present.

If, and only if, that exact mapping is absent from the approved checkout:

```bash
firebase target:apply hosting blitz master-intelligence-5496f-lb --project master-intelligence-5496f
```

Then `git diff -- .firebaserc` must be empty, or must show only that one mapping. If the diff points `blitz` at the default site, Meeting Prep, the app site, or any other ID, restore the file and stop. `target:apply` writes `.firebaserc` locally. It does not create a site.

## (c) Guarded synthetic deploy

```bash
unset DASHBOARD_PASSPHRASE
export BLITZ_APPROVE_SYNTHETIC_DEPLOY=YES
bash scripts/deploy-firebase-demo.sh
```

The script refuses to continue unless all of the following are true:

- It is not running under `CI` or `GITHUB_ACTIONS`.
- `BLITZ_APPROVE_SYNTHETIC_DEPLOY` is exactly `YES`.
- `DASHBOARD_PASSPHRASE` is unset.
- `.firebaserc` maps only `blitz` to `master-intelligence-5496f-lb` in project `master-intelligence-5496f`.
- `firebase.json` contains only `hosting` for target `blitz`, public directory `.firebase-blitz-demo`, and no Firestore, Functions, Storage, Realtime Database, emulators, or rewrites.
- `npm test`, `npm run verify:bundle`, `npm run build:firebase-demo`, and `npm run verify:firebase-demo` pass. Those checks require four fictional contacts, an exact file allowlist, and a synthetic ciphertext that is not the GitHub Pages bundle.
- `firebase hosting:sites:list --project master-intelligence-5496f --json --non-interactive` contains the exact Blitz site resource. A longer or shorter ID does not count. The script does not create the site.

The only deploy command in the script is:

```bash
firebase deploy --only hosting:blitz --project master-intelligence-5496f --non-interactive
```

Do not run a bare `firebase deploy`. Do not pass `--only hosting`, `--only firestore`, `--only functions`, or `--only storage`.

## (d) Live verification

1. Open `https://master-intelligence-5496f-lb.web.app` (and the `firebaseapp.com` host only as a second check). The title must say `SYNTHETIC DEMO`.
2. Unlock with the public demo passphrase printed on that lock screen. It is the synthetic constant in `scripts/build-firebase-demo.mjs`, not the production passphrase.
3. Confirm the example banner and exactly four fictional contacts: Example Ada, Example Ben, Example Cy, and Example Di. Open each contact and use Lock.
4. Compare hashes, without decrypting the Pages file:

```bash
curl -fsS https://master-intelligence-5496f-lb.web.app/data.enc.json | sha256sum
sha256sum docs/data.enc.json
```

The hashes must differ. The hosted file is the small synthetic bundle. The Pages file stays the large published bundle.

5. Confirm `https://smg980.github.io/linkedin-blitz-dashboard/` still loads and was not modified by this deploy.
6. Confirm the default MASTER site, Meeting Prep, and `master-intelligence-5496f-app` still show their previous content.
7. Do not add `blitz.masterintelligence.ai` or any other DNS record in this step.

## (e) Rollback

GitHub Pages is the live campaign and is the fallback. Do not delete `docs/data.enc.json`.

To take only the new Blitz site offline:

```bash
firebase hosting:disable --project master-intelligence-5496f --site master-intelligence-5496f-lb --force
```

`--site` is required. Do not disable `master-intelligence-5496f`, `master-intelligence-5496f-prep`, or `master-intelligence-5496f-app`. `--non-interactive` without `--force` aborts and does not disable the site. A later approved run of the guarded deploy publishes a new version and serves the site again.

Permanent removal, only if Steven separately asks to delete the site:

```bash
firebase hosting:sites:delete master-intelligence-5496f-lb --project master-intelligence-5496f --force
```

Deletion removes that site's deploy history and cannot be undone. It must not be used on any other site ID.
