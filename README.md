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
