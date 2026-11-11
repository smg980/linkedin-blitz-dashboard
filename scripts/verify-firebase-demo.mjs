#!/usr/bin/env node
// Verifies a synthetic-only, standalone Firebase Hosting output. No credentials.
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { webcrypto } from 'node:crypto';
import { DEMO_PASSPHRASE } from './build-firebase-demo.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const OUT = path.join(ROOT, '.firebase-blitz-demo');

export async function verify() {
  const rc = JSON.parse(await fs.readFile(path.join(ROOT, '.firebaserc'), 'utf8'));
  const config = JSON.parse(await fs.readFile(path.join(ROOT, 'firebase.json'), 'utf8'));
  const target = rc.targets?.['master-intelligence-5496f']?.hosting?.blitz;
  if (!Array.isArray(target) || target.length !== 1 || target[0].length > 30 ||
      target[0] !== 'master-intelligence-5496f-lb') throw new Error('Firebase blitz target is invalid');
  if (JSON.stringify(Object.keys(config)) !== JSON.stringify(['hosting']) ||
      config.hosting.target !== 'blitz' || config.hosting.public !== '.firebase-blitz-demo')
    throw new Error('Firebase config must target only the isolated synthetic Blitz site');
  const headers = config.hosting.headers?.find(x => x.source === '**')?.headers || [];
  const map = Object.fromEntries(headers.map(x => [x.key.toLowerCase(), x.value]));
  for (const key of ['content-security-policy', 'cache-control', 'x-content-type-options', 'x-robots-tag']) {
    if (!map[key]) throw new Error('Missing Hosting security header: ' + key);
  }
  if (!map['content-security-policy'].includes("default-src 'self'") ||
      !map['content-security-policy'].includes("frame-ancestors 'none'") ||
      map['cache-control'] !== 'no-store')
    throw new Error('Hosting security policy is weakened');

  async function listFiles(relative = '') {
    const entries = await fs.readdir(path.join(OUT, relative), { withFileTypes: true });
    const files = [];
    for (const entry of entries) {
      const filename = path.posix.join(relative, entry.name);
      if (entry.isDirectory()) files.push(...await listFiles(filename));
      else if (entry.isFile()) files.push(filename);
      else throw new Error('Unexpected Firebase deploy file type: ' + filename);
    }
    return files.sort();
  }
  const filenames = await listFiles();
  const allowed = [
    'index.html','app.js','theme.css','blitz.css','favicon.ico','data.enc.json',
    'fonts/DMSans-latin.woff2','fonts/Manrope-latin.woff2',
    'img/apple-touch-icon.png','img/favicon-32.png',
    'img/logo-header.png','img/logo-header.webp','img/logo-lock.png','img/logo-lock.webp',
  ].sort();
  if (JSON.stringify(filenames) !== JSON.stringify(allowed)) throw new Error('Unexpected Firebase deploy file');

  const html = await fs.readFile(path.join(OUT, 'index.html'), 'utf8');
  if (!html.includes('SYNTHETIC DATA ONLY') || !html.includes(DEMO_PASSPHRASE))
    throw new Error('Synthetic-only unlock label missing');
  const srcBytes = await fs.readFile(path.join(ROOT, 'docs', 'data.enc.json'));
  const bundleBytes = await fs.readFile(path.join(OUT, 'data.enc.json'));
  if (srcBytes.equals(bundleBytes)) throw new Error('Live campaign ciphertext was copied into synthetic Hosting output');

  const blob = JSON.parse(bundleBytes.toString('utf8'));
  if (blob.v !== 1 || blob.alg !== 'AES-256-GCM' || blob.kdf !== 'PBKDF2-SHA256' ||
      blob.iterations !== 600000 || Object.keys(blob).length !== 7) throw new Error('Unexpected demo encryption format');
  const imported = await webcrypto.subtle.importKey('raw', new TextEncoder().encode(DEMO_PASSPHRASE), 'PBKDF2', false, ['deriveKey']);
  const key = await webcrypto.subtle.deriveKey({
    name: 'PBKDF2', hash: 'SHA-256', salt: Buffer.from(blob.salt, 'base64'),
    iterations: blob.iterations
  }, imported, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
  const plain = await webcrypto.subtle.decrypt(
    { name: 'AES-GCM', iv: Buffer.from(blob.iv, 'base64') }, key, Buffer.from(blob.ct, 'base64')
  );
  const data = JSON.parse(new TextDecoder().decode(plain));
  if (data.example !== true || data.contacts?.length !== 4 ||
      !data.contacts.every(x => x.account.startsWith('EXAMPLE ') && x.contact.startsWith('Example ')) ||
      !data.campaign?.name?.startsWith('EXAMPLE'))
    throw new Error('Firebase preview has non-synthetic campaign records');
  return { contacts: data.contacts.length, target: target[0] };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  verify().then(x => console.log('Firebase synthetic preview verified: ' + x.contacts + ' fictional contacts.'))
    .catch(e => { console.error('Firebase preview verification failed: ' + e.message); process.exitCode = 1; });
}
