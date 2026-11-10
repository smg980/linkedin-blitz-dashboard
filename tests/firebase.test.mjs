import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { verify } from '../scripts/verify-firebase-demo.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const builder = path.join(root, 'scripts', 'build-firebase-demo.mjs');

test('Firebase preview builds with only four fictional encrypted contacts', async () => {
  const env = { ...process.env };
  delete env.DASHBOARD_PASSPHRASE;
  const result = spawnSync(process.execPath, [builder], { cwd: root, env, encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr || result.stdout);
  const proof = await verify();
  assert.equal(proof.contacts, 4);
  assert.equal(proof.target, 'master-intelligence-5496f-lb');
});

test('synthetic builder rejects accidentally inherited production credentials', () => {
  const result = spawnSync(process.execPath, [builder], {
    cwd: root, env: { ...process.env, DASHBOARD_PASSPHRASE: 'DO-NOT-USE-REAL-SECRETS' },
    encoding: 'utf8'
  });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Do not run the synthetic Firebase builder with a real dashboard passphrase/);
});
