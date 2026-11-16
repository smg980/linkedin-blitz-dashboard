// Offline fail-closed verification for the private LinkedIn Blitz Hosting target.
// This file never writes to Firebase. The deploy wrapper runs all cloud reads.
import fs from 'node:fs';
import path from 'node:path';
import { verifySecureShell, SECURE_OUT } from './verify-secure-shell.mjs';
import { assertExactSiteListed, PROJECT, SITE, TARGET } from './blitz-hosting-guard.mjs';

const ALLOWED_AUTH_DOMAINS = new Set([
  `${PROJECT}.firebaseapp.com`,
  `${SITE}.web.app`,
]);
const ALLOWED_HOSTING_KEYS = new Set(['target', 'public', 'ignore', 'headers']);
const PUBLIC_API_KEY = /^AIza[A-Za-z0-9_-]{30,}$/;
const PUBLIC_APP_ID = /^1:\d+:web:[A-Za-z0-9]+$/;
const RESOURCE_ID = '[A-Za-z0-9_-]{1,128}';

function escaped(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

export function assertSecureTarget(rc, config) {
  if (rc?.projects?.default !== PROJECT) throw new Error('Wrong Firebase project');
  if (JSON.stringify(rc?.targets?.[PROJECT]?.hosting) !== JSON.stringify({ [TARGET]: [SITE] })) {
    throw new Error('Hosting target must map only to dedicated Blitz site');
  }
  if (Object.keys(rc?.targets || {}).length !== 1 || Object.keys(rc?.targets?.[PROJECT] || {}).length !== 1) {
    throw new Error('Unexpected Firebase target mapping');
  }
  if (!config || Object.keys(config).length !== 1 || !config.hosting || Array.isArray(config.hosting)) {
    throw new Error('Private Firebase config must contain hosting only');
  }
  for (const key of Object.keys(config.hosting)) {
    if (!ALLOWED_HOSTING_KEYS.has(key)) throw new Error('Unexpected private Hosting setting: ' + key);
  }
  if (config.hosting.target !== TARGET || config.hosting.public !== '.firebase-blitz-private-shell') {
    throw new Error('Wrong private Hosting target or output directory');
  }
  if (config.hosting.rewrites || config.hosting.redirects || config.hosting.predeploy || config.hosting.postdeploy) {
    throw new Error('No rewrites, redirects, or deploy hooks are permitted');
  }
}

export function assertPrivateWebConfig(text) {
  const prefix = 'globalThis.BLITZ_SECURE_CONFIG = ';
  if (!text.startsWith(prefix) || !text.trimEnd().endsWith(';')) throw new Error('Invalid built web config');
  const obj = JSON.parse(text.slice(prefix.length).trim().replace(/;$/, ''));
  if (obj.useEmulators !== false || obj.emulators) throw new Error('Refusing emulator-configured Hosting output');
  if (Object.keys(obj).sort().join(',') !== 'firebase,useEmulators') throw new Error('Unexpected web config keys');
  if (obj.firebase?.projectId !== PROJECT || !ALLOWED_AUTH_DOMAINS.has(obj.firebase?.authDomain)) {
    throw new Error('Wrong project or unapproved authentication domain in web config');
  }
  if (Object.keys(obj.firebase).sort().join(',') !== 'apiKey,appId,authDomain,projectId') {
    throw new Error('Unexpected Firebase web config fields');
  }
  if (Object.values(obj.firebase).some(v => typeof v !== 'string' || !v || /[\s"'{}]|REPLACE_|CHANGEME|emulator-placeholder|private_key|BEGIN /i.test(v))) {
    throw new Error('Missing or placeholder Firebase web config');
  }
  if (!PUBLIC_API_KEY.test(obj.firebase.apiKey) || !PUBLIC_APP_ID.test(obj.firebase.appId)) {
    throw new Error('Firebase web config is not a public apiKey and web appId');
  }
  return obj;
}

// Parses GET sites/{site}/channels/live. The channel's `release` is the version
// currently being served. A releases.list page is not that value: its order is
// not documented, and pageSize is only a maximum.
export function currentLiveRelease(text) {
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    throw new Error('Hosting channel response was not JSON');
  }
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    throw new Error('Hosting channel response was not a resource');
  }
  if (Array.isArray(data.releases) || data.nextPageToken != null || Array.isArray(data.channels) || Array.isArray(data.sites)) {
    throw new Error('Expected the live channel resource, not a paged list');
  }
  if (data.name !== `sites/${SITE}/channels/live`) throw new Error('Response is not the dedicated Blitz live channel');
  if (data.url !== `https://${SITE}.web.app`) throw new Error('Live channel URL is not the dedicated Blitz site');
  const release = data.release;
  if (!release || typeof release !== 'object' || Array.isArray(release)) {
    throw new Error('Live channel has no current release');
  }
  const site = escaped(SITE);
  const releaseName = typeof release.name === 'string' ? release.name : '';
  const releaseOk = new RegExp(`^sites/${site}/channels/live/releases/${RESOURCE_ID}$`).test(releaseName)
    || new RegExp(`^sites/${site}/releases/${RESOURCE_ID}$`).test(releaseName);
  if (!releaseOk) throw new Error('Release is not an exact dedicated-site live release id');
  const versionName = typeof release.version?.name === 'string' ? release.version.name : '';
  const versionMatch = new RegExp(`^sites/${site}/versions/(${RESOURCE_ID})$`).exec(versionName);
  if (!versionMatch) throw new Error('Release lacks an exact restorable version ID');
  if (release.version.status !== 'FINALIZED') throw new Error('Live version is not a finalized Hosting version');
  if (release.type != null && release.type !== 'DEPLOY' && release.type !== 'TYPE_UNSPECIFIED') {
    throw new Error('Current Hosting release is not a deploy');
  }
  return { release: releaseName, version: versionName, versionId: versionMatch[1] };
}

function parseJson(file) { return JSON.parse(fs.readFileSync(file, 'utf8')); }

async function main() {
  const mode = process.argv[2];
  if (mode === '--assert-config') {
    assertSecureTarget(parseJson('.firebaserc'), parseJson('firebase.secure-blitz.json'));
    console.log('PASS: private shell release targets only hosting:blitz');
  } else if (mode === '--assert-shell') {
    const result = await verifySecureShell(SECURE_OUT);
    assertPrivateWebConfig(fs.readFileSync(path.join(SECURE_OUT, 'config.js'), 'utf8'));
    if (result.emulator) throw new Error('Production shell is using emulators');
    console.log(`PASS: production-only secure Hosting output verified (${result.files} files, no campaign data)`);
  } else if (mode === '--require-site') {
    assertExactSiteListed(fs.readFileSync(0, 'utf8'), SITE);
    console.log('PASS: dedicated Blitz Hosting site exists');
  } else if (mode === '--release') {
    const value = currentLiveRelease(fs.readFileSync(0, 'utf8'));
    console.log(value.release);
    console.log(value.version);
    console.log(value.versionId);
  } else {
    throw new Error('Use --assert-config, --assert-shell, --require-site, or --release');
  }
}

if (process.argv[1] && process.argv[1].endsWith('secure-hosting-guard.mjs')) {
  main().catch(e => { console.error(`STOP: ${e.message}`); process.exitCode = 1; });
}
