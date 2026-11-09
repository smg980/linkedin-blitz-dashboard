#!/usr/bin/env node
// A secret-free release check for the public encrypted GitHub Pages bundle.
// This validates its envelope and required assets, not the decrypted campaign.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const FIELDS = ['alg', 'ct', 'iterations', 'iv', 'kdf', 'salt', 'v'];

function decodeCanonicalBase64(value, field) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) {
    throw new Error(`${field} must be canonical base64`);
  }
  const bytes = Buffer.from(value, 'base64');
  if (!bytes.length || bytes.toString('base64') !== value) {
    throw new Error(`${field} has invalid base64 encoding`);
  }
  return bytes;
}

export function validatePublishedBundle(blob) {
  if (!blob || Array.isArray(blob) || typeof blob !== 'object') {
    throw new Error('Encrypted bundle must be a JSON object');
  }
  if (JSON.stringify(Object.keys(blob).sort()) !== JSON.stringify(FIELDS)) {
    throw new Error('Encrypted bundle must contain only the approved envelope fields');
  }
  if (blob.v !== 1 || blob.alg !== 'AES-256-GCM' || blob.kdf !== 'PBKDF2-SHA256' || blob.iterations !== 600000) {
    throw new Error('Unsupported encryption envelope or KDF parameters');
  }
  if (decodeCanonicalBase64(blob.salt, 'salt').length !== 16) throw new Error('Salt must be 16 bytes');
  if (decodeCanonicalBase64(blob.iv, 'iv').length !== 12) throw new Error('IV must be 12 bytes');
  const bytes = decodeCanonicalBase64(blob.ct, 'ct');
  if (bytes.length < 17) throw new Error('Ciphertext must contain an AES-GCM authentication tag');
  return { ciphertextBytes: bytes.length, iterations: blob.iterations };
}

function run() {
  const encryptedPath = path.join(ROOT, 'docs', 'data.enc.json');
  const data = JSON.parse(fs.readFileSync(encryptedPath, 'utf8'));
  const result = validatePublishedBundle(data);

  const html = fs.readFileSync(path.join(ROOT, 'docs', 'index.html'), 'utf8');
  if (!html.includes("default-src 'self'; script-src 'self'") || !html.includes("form-action 'none'")) {
    throw new Error('GitHub Pages entrypoint has lost its strict CSP');
  }
  for (const asset of ['app.js', 'theme.css', 'blitz.css']) {
    const matches = [...html.matchAll(new RegExp('(?:src|href)="' + asset.replace('.', '\\.') + '(?:\\?v=[0-9]+)?"', 'g'))];
    if (matches.length !== 1 || !fs.statSync(path.join(ROOT, 'docs', asset)).isFile()) {
      throw new Error(`Missing or duplicated local asset reference: ${asset}`);
    }
  }
  console.log(`Public encrypted bundle OK: ${result.ciphertextBytes} ciphertext bytes, ${result.iterations} PBKDF2 iterations; no key or decryption required.`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { run(); } catch (error) { console.error(`Published bundle FAIL: ${error.message}`); process.exitCode = 1; }
}
