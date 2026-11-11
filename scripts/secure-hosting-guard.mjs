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
  if (Object.values(obj.firebase).some(v => typeof v !== 'string' || !v || /REPLACE_|CHANGEME|emulator-placeholder/i.test(v))) {
    throw new Error('Missing or placeholder Firebase web config');
  }
  return obj;
}

export function latestRelease(text) {
  const data = JSON.parse(text);
  const list = data.releases;
  if (!Array.isArray(list) || !list.length) throw new Error('No Hosting releases were returned');
  if (list.length !== 1) throw new Error('Expected exactly one release from pageSize=1');
  const release = list[0];
  if (typeof release.name !== 'string' || !release.name.startsWith(`sites/${SITE}/channels/live/releases/`)) {
    throw new Error('Release is not in the dedicated live channel');
  }
  if (typeof release.version?.name !== 'string' || !release.version.name.startsWith(`sites/${SITE}/versions/`)) {
    throw new Error('Release lacks a restorable version ID');
  }
  if (release.type && release.type !== 'DEPLOY') throw new Error('Current Hosting release is not a deploy');
  return { release: release.name, version: release.version.name };
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
    const value = latestRelease(fs.readFileSync(0, 'utf8'));
    console.log(value.release);
    console.log(value.version);
  } else {
    throw new Error('Use --assert-config, --assert-shell, --require-site, or --release');
  }
}

if (process.argv[1] && process.argv[1].endsWith('secure-hosting-guard.mjs')) {
  main().catch(e => { console.error(`STOP: ${e.message}`); process.exitCode = 1; });
}
