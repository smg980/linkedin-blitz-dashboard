# MASTER INTELLIGENCE · LinkedIn Blitz Dashboard

A static, passphrase-locked dashboard (GitHub Pages) for a LinkedIn engagement campaign. It uses the same template, theme and encryption scheme as the Meeting Prep dashboard.

- **Everything sensitive is encrypted.** The only campaign data in this repo is `docs/data.enc.json`:
  AES-256-GCM, key derived with PBKDF2-SHA256 (600,000 iterations, random 16-byte salt, random 12-byte IV, fresh on every build).
- **Decryption happens in your browser** with Web Crypto. No server, no analytics, no third-party requests (strict CSP, `noindex`).
- The source files live outside this repo. Emails and phone numbers are stripped before encryption.
- Preparation only: nothing is sent from here.

## Views (hash routes, after unlock)
`#/` overview (campaign dates, accounts, day-by-account schedule, status counts) · `#/briefs` and `#/doc/<id>` daily briefs and plans ·
`#/accounts` per-account contact queue with status badges · `#/contact/<id>` drafts, sources, checks · `#/needs` items needing the seller.
Ids are opaque hashes.

## Building
```bash
export DASHBOARD_PASSPHRASE='…'      # required, never commit it
BLITZ_DIR=/path/to/source node scripts/build.mjs   # writes docs/data.enc.json
```
`--dry-run` prints counts only. `--example` builds a labeled EXAMPLE dataset into `example/` (gitignored).

## Brand / theme
`docs/theme.css` is the Meeting Prep stylesheet, unchanged. All colors are CSS variables in its single `:root` block.
`docs/blitz.css` adds campaign components and uses only those tokens. Fonts (Manrope headings, DM Sans body) and the official MASTER Intelligence logo are self-hosted.

## Testing and release safety
Run `npm test` with Node.js 20+ before proposing a change. GitHub Actions runs synthetic-only tests on pull requests and on merges to `main`. Tests include browser queue behavior, explicit draft copying, encryption round-trip, randomized salt/IV, PII scrubbing, and fail-closed build validation.

To build without touching the live `docs/data.enc.json`, provide a separate output path:
```bash
BLITZ_DIR=/path/to/private/source BLITZ_OUTPUT_DIR=/tmp/blitz-qa \
  DASHBOARD_PASSPHRASE='your-existing-strong-passphrase' node scripts/build.mjs
```
Use `--dry-run` for counts only (no encryption or output). `--example --dry-run` works without access to private campaign sources. `--plain-check` is limited to synthetic example builds and must never be used on real campaign data.

The live GitHub Pages application is served from `main/docs`. Make changes in a feature branch, wait for passing PR checks, review the diff, then merge. The encrypted production dataset should not be regenerated merely to publish code improvements.

**Security boundaries:** The ciphertext is publicly downloadable on GitHub Pages even though its contents are encrypted. Keep a strong, unique passphrase outside GitHub and do not expose it through CI or logs. The "Keep unlocked in this tab" setting stores that passphrase in tab-scoped session storage until locked or the tab closes. The app never sends LinkedIn messages or claims a touch was sent without confirmation.

## Contact queue operation
Contact cards are grouped by **account and full contact name**, even for older encrypted snapshots whose original first-name keys may collide. A future source build also uses full-name-derived opaque person IDs. Filtering is read-only and never changes an outreach status. Use the shareable URL fragments `#/accounts?filter=overdue`, `#/accounts?filter=today`, and `#/accounts?filter=actionable` (or choose a specific status). These counts are **contacts**, not touches. A person is actionable when at least one row is Draft Ready, Approved, or Next Action; this is not authorization to send. The visible status is the earliest outstanding next touch; past sent/held rows stay intact in contact detail.

The UI warns when its decrypted dataset was built over 48 hours ago or lacks a valid `generatedAt`. Freshness is advisory, not evidence that the source statuses are accurate. Rebuilds require access to the private source files and the existing passphrase. **Do not collect a GitHub password, LinkedIn token, or dashboard passphrase through a public issue.**

## Verify the published ciphertext without credentials
`npm run verify:bundle` checks the committed GitHub Pages ciphertext's exact AES-GCM/PBKDF2 metadata, canonical base64 encoding, salt/IV/tag lengths, and references to locally hosted JavaScript/CSS. It does **not** decrypt or inspect private contacts. CI runs this check on each PR alongside the synthetic-data tests. Successful verification proves structural validity, not that the campaign content is current or that the passphrase is correct.

GitHub's branch-hosted Pages deployment is a separate process; these checks run on the pull request before *our* merge, but this workflow does not by itself enforce repository branch protection. A repository administrator should separately require the `test` check on merges if protection is not already configured.

## Firebase migration staging — next to Meeting Prep

A separate **synthetic-only** Firebase Hosting candidate is prepared for the existing Firebase project `master-intelligence-5496f`. Target `blitz` maps to the **proposed**, not yet created, site `master-intelligence-5496f-lb`; planned custom domain is `blitz.masterintelligence.ai`. This does not deploy or change the Meeting Prep `prep` site, MASTER application, existing GitHub Pages URL, production campaign ciphertext or passphrase.

Run `npm test` to validate the staging safeguards, or `npm run build:firebase-demo && npm run verify:firebase-demo` to generate and verify the four-contact fictional preview under the Gitignored `.firebase-blitz-demo/` directory. It refuses an inherited production passphrase and never copies `docs/data.enc.json`. Do not publish real outreach data directly to Firebase Hosting: static Hosting files are publicly retrievable.

**Production migration remains gated** on the Meeting Prep Firebase Auth/Firestore authorization review, merged security rules tests, secure access to encrypted data, approved passphrase rotation and separate `hosting:blitz` deployment. See [Firebase Blitz migration plan](docs/FIREBASE_BLITZ_MIGRATION.md). The live GitHub Pages campaign remains the rollback.
