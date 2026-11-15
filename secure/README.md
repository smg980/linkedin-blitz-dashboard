# Private LinkedIn Blitz shell

This directory is the source for a Firebase Hosting app shell. The built site contains HTML, CSS, JavaScript, fonts, and images. It does not contain a campaign file or ciphertext.

After Google sign-in the browser force-refreshes the ID token once, then reads one Firestore document, `blitzOwners/{signed-in uid}/campaign/current`, with a single get. It never lists or queries. The document holds the same client-side AES-256-GCM envelope the public dashboard already uses. The passphrase is typed into the page and decryption stays in the browser. A missing document or a permission denial shows not authorized. Lock and sign-out drop the decrypted value from the page. The passphrase and the decrypted campaign are not written to web storage.

The client does not write to Firestore, does not list the collection, and does not send LinkedIn messages or status changes.

Access rules for the live project are prepared separately. This client treats a missing document and a permission denial as not authorized and offers sign-out. It does not embed an owner identity.

## Sign-in on iPhone Safari

Desktop browsers start with the Google popup. iPhone Safari starts with a redirect only when `authDomain` is the host that serves the shell (or in the loopback emulator). With the default `master-intelligence-5496f.firebaseapp.com` authDomain the shell is on a different site, Safari 16.1+ blocks the storage that `getRedirectResult` reads, and a redirect would return signed out. In that case iPhone Safari uses the popup too. If the popup is blocked and a redirect cannot complete, the shell asks the user to allow pop-ups instead of redirecting.

Setting `authDomain` to `master-intelligence-5496f-lb.web.app` would let iPhone Safari use the redirect again. That also needs `https://master-intelligence-5496f-lb.web.app/__/auth/handler` as an authorized redirect URI on the OAuth client, which is a Firebase Auth configuration change with its own approval. The emulator test cannot prove either path on a physical iPhone; test on a device before relying on it.

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
