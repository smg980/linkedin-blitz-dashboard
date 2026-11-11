#!/usr/bin/env node
// Fails if the private Hosting shell contains campaign data or ciphertext.
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { productionCsp } from '../secure/csp.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const SECURE_OUT = path.join(ROOT, '.firebase-blitz-private-shell');
export const SECURE_SHELL_FILES = [
  'index.html',
  'shell.js',
  'shell.css',
  'config.js',
  'theme.css',
  'blitz.css',
  'favicon.ico',
  'fonts/DMSans-latin.woff2',
  'fonts/Manrope-latin.woff2',
  'img/apple-touch-icon.png',
  'img/favicon-32.png',
  'img/logo-header.png',
  'img/logo-header.webp',
  'img/logo-lock.png',
  'img/logo-lock.webp',
].sort();

export const FORBIDDEN_SNIPPETS = [
  'Example Ada',
  'Example Ben',
  'Example Cy',
  'Example Di',
  'EXAMPLE Acme',
  'EXAMPLE Globex',
  'SYNTHETIC-BLITZ-DEMO-ONLY-2026',
  'owner-synthetic@example.com',
  'intruder-synthetic@example.com',
  'data.enc.json',
];

const TEXT_EXT = new Set(['.html', '.js', '.css', '.json', '.txt', '.map', '.svg']);

async function listFiles(root, relative = '') {
  const entries = await fs.readdir(path.join(root, relative), { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const file = path.posix.join(relative, entry.name);
    if (entry.isDirectory()) files.push(...await listFiles(root, file));
    else if (entry.isFile()) files.push(file);
    else throw new Error('Unexpected file in secure shell: ' + file);
  }
  return files.sort();
}

function assertSecureHostingConfig(config) {
  if (!config || JSON.stringify(Object.keys(config)) !== JSON.stringify(['hosting'])) {
    throw new Error('firebase.secure-blitz.json must contain only hosting');
  }
  const hosting = config.hosting;
  if (hosting?.target !== 'blitz' || hosting.public !== '.firebase-blitz-private-shell') {
    throw new Error('Secure hosting config must target blitz and the private shell directory');
  }
  if (hosting.rewrites || hosting.redirects) throw new Error('Secure hosting config must not rewrite or redirect');
  const headers = hosting.headers?.find((item) => item.source === '**')?.headers || [];
  const map = Object.fromEntries(headers.map((item) => [item.key.toLowerCase(), item.value]));
  if (map['content-security-policy'] !== productionCsp()) throw new Error('Secure shell CSP drifted from the production policy');
  if (map['cache-control'] !== 'no-store') throw new Error('Secure shell must send Cache-Control: no-store');
  if (!map['x-robots-tag']?.includes('noindex')) throw new Error('Secure shell must send noindex');
  if (/localhost|127\.0\.0\.1|unsafe-inline|unsafe-eval/i.test(map['content-security-policy'])) {
    throw new Error('Production CSP must not allow emulator hosts or inline scripts');
  }
  const serialized = JSON.stringify(config);
  if (/data\.enc\.json|AIza|firestore\.rules|owner@|apiKey/i.test(serialized)) {
    throw new Error('Secure hosting config contains data or a client secret field');
  }
}

export async function verifySecureShell(dir = SECURE_OUT) {
  const config = JSON.parse(await fs.readFile(path.join(ROOT, 'firebase.secure-blitz.json'), 'utf8'));
  assertSecureHostingConfig(config);
  const files = await listFiles(dir);
  if (JSON.stringify(files) !== JSON.stringify(SECURE_SHELL_FILES)) {
    throw new Error('Secure shell file list is not the allowlist: ' + files.join(', '));
  }
  const html = await fs.readFile(path.join(dir, 'index.html'), 'utf8');
  const built = await fs.readFile(path.join(dir, 'config.js'), 'utf8');
  if (!html.includes('Content-Security-Policy') || html.includes('unsafe-inline') || html.includes('unsafe-eval')) {
    throw new Error('Secure shell HTML CSP is missing or relaxed');
  }
  const emulator = built.includes('"useEmulators":true');
  if (emulator) {
    if (!html.includes('127.0.0.1') && !html.includes('localhost')) throw new Error('Emulator shell CSP is missing its loopback origin');
    if (built.includes('AIza')) throw new Error('Emulator shell must not contain a live API key');
  } else {
    const meta = html.match(/Content-Security-Policy" content="([^"]*)"/);
    if (!meta || /127\.0\.0\.1|localhost/.test(meta[1])) throw new Error('Production shell CSP must not allow loopback');
    if (meta[1] !== productionCsp()) throw new Error('Production shell CSP does not match firebase.secure-blitz.json');
  }
  for (const file of files) {
    const full = path.join(dir, file);
    const bytes = await fs.readFile(full);
    const text = bytes.toString('latin1');
    for (const snippet of FORBIDDEN_SNIPPETS) {
      if (text.includes(snippet)) throw new Error('Secure shell contains forbidden data: ' + snippet + ' in ' + file);
    }
    if (/"ct"\s*:\s*"[A-Za-z0-9+/=]{40,}"/.test(text)) throw new Error('Secure shell contains ciphertext in ' + file);
    if (TEXT_EXT.has(path.extname(file))) {
      if (/"salt"\s*:/.test(text) && /"iv"\s*:/.test(text) && /"ct"\s*:/.test(text)) {
        throw new Error('Secure shell contains an encryption envelope in ' + file);
      }
    }
  }
  if (!emulator && !built.includes('"useEmulators":false')) throw new Error('Secure shell config is missing an emulator flag');
  return { files: files.length, emulator };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  verifySecureShell().then((result) => {
    console.log(`Secure shell verified: ${result.files} files, no campaign ciphertext.`);
  }).catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}
