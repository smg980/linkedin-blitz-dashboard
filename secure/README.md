# Private LinkedIn Blitz shell

This directory is the source for a Firebase Hosting app shell. The built site contains HTML, CSS, JavaScript, fonts, and images. It does not contain a campaign file or ciphertext.

After Google sign-in the browser force-refreshes the ID token once, then reads one Firestore document, `blitzOwners/{signed-in uid}/campaign/current`, with a single get. It never lists or queries. The document holds the same client-side AES-256-GCM envelope the public dashboard already uses. The passphrase is typed into the page and decryption stays in the browser. A missing document or a permission denial shows not authorized. Lock and sign-out drop the decrypted value from the page. The passphrase and the decrypted campaign are not written to web storage.

The client does not write to Firestore, does not list the collection, and does not send LinkedIn messages or status changes.

Access rules for the live project are prepared separately. This client treats a missing document and a permission denial as not authorized and offers sign-out. It does not embed an owner identity.

## Local proof

```bash
npm test
npm run test:secure
```

`test:secure` starts the Auth and Firestore emulators, encrypts the four fictional demo contacts, and writes that envelope to the emulator only. A headless browser then opens the built shell at a 390×844 viewport.

`scripts/ingest-synthetic-emulator.mjs` refuses any host that is not a loopback emulator and any project id that does not start with `demo-`. It has no input flag for another dataset.

## Real campaign data

Loading the live campaign, or any real contacts, is not part of this tool. That remains a separate approved step and must use an approved source. Do not point this ingestion tool at production.

## Hosting config

`firebase.secure-blitz.json` is hosting-only, for a future deploy of this shell to the existing `blitz` target. It is not wired to `scripts/deploy-firebase-demo.sh`. This repository does not add a deploy command for the private shell. A later deploy needs its own explicit approval, the same kind of guard the fictional demo script already uses, plus a Firebase web config supplied outside git (`secure-config.local.json`).

Build the shell with that untracked file, or build the emulator placeholder with:

```bash
npm run build:secure-shell -- --emulator
npm run verify:secure-shell
```

The verifier fails the build if the output contains a data file, ciphertext, or the known fictional contact names.
