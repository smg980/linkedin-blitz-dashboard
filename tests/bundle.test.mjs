import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { validatePublishedBundle } from '../scripts/check-published.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const valid = {
  v: 1, alg: 'AES-256-GCM', kdf: 'PBKDF2-SHA256', iterations: 600000,
  salt: Buffer.alloc(16, 10).toString('base64'),
  iv: Buffer.alloc(12, 11).toString('base64'),
  ct: Buffer.alloc(64, 12).toString('base64')
};

test('shipped encrypted bundle has only the expected ciphertext envelope', () => {
  const blob = JSON.parse(readFileSync(path.join(root, 'docs', 'data.enc.json'), 'utf8'));
  const stats = validatePublishedBundle(blob);
  assert.ok(stats.ciphertextBytes >= 17);
  assert.equal(stats.iterations, 600000);
});

test('reject unsupported, altered, or plaintext bundle fields', () => {
  assert.equal(validatePublishedBundle(valid).ciphertextBytes, 64);
  assert.throws(() => validatePublishedBundle({ ...valid, contacts: ['plaintext'] }), /only the approved/);
  assert.throws(() => validatePublishedBundle({ ...valid, iterations: 1000 }), /Unsupported/);
  assert.throws(() => validatePublishedBundle({ ...valid, salt: '!invalid!' }), /canonical base64/);
  assert.throws(() => validatePublishedBundle({ ...valid, iv: Buffer.alloc(9).toString('base64') }), /12 bytes/);
  assert.throws(() => validatePublishedBundle({ ...valid, ct: Buffer.alloc(12).toString('base64') }), /authentication tag/);
  assert.throws(() => validatePublishedBundle(null), /JSON object/);
});
