import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import fs from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { runInNewContext } from 'node:vm';
import { readFileSync } from 'node:fs';
import { webcrypto } from 'node:crypto';
import { DEMO_PASSPHRASE } from '../scripts/build-firebase-demo.mjs';
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

test('Firebase preview rejects extra nested assets rather than hiding them in copied directories', async () => {
  const env = { ...process.env };
  delete env.DASHBOARD_PASSPHRASE;
  const result = spawnSync(process.execPath, [builder], { cwd: root, env, encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr || result.stdout);
  const extraneous = path.join(root, '.firebase-blitz-demo', 'img', 'unexpected-export.csv');
  await fs.writeFile(extraneous, 'synthetic-test-only');
  try {
    await assert.rejects(verify(), /Unexpected Firebase deploy file/);
  } finally {
    await fs.rm(extraneous, { force: true });
  }
  await verify();
});

// Exercise the exact staged JS and encrypted synthetic payload, not a second test fixture.
// Browser rendering is simulated offline: no Firebase, real contacts, credentials or network.
test('staged Firebase Blitz unlocks four fictional contacts and navigates read-only', async () => {
  const env = { ...process.env };
  delete env.DASHBOARD_PASSPHRASE;
  const built = spawnSync(process.execPath, [builder], { cwd: root, env, encoding: 'utf8' });
  assert.equal(built.status, 0, built.stderr || built.stdout);
  assert.deepEqual(await verify(), { contacts: 4, target: 'master-intelligence-5496f-lb' });

  const staged = path.join(root, '.firebase-blitz-demo');
  const blob = JSON.parse(await fs.readFile(path.join(staged, 'data.enc.json'), 'utf8'));
  const html = await fs.readFile(path.join(staged, 'index.html'), 'utf8');
  assert.match(html, /SYNTHETIC DATA ONLY/);
  assert.match(html, /SYNTHETIC-BLITZ-DEMO-ONLY-2026/);

  const nodes = new Map();
  const handlers = new Map();
  const node = selector => {
    if (!nodes.has(selector)) nodes.set(selector, {
      innerHTML: '', textContent: '', hidden: false, value: '', checked: false,
      disabled: false, className: '', focus() {},
      addEventListener(event, fn) { handlers.set(selector + ':' + event, fn); },
    });
    return nodes.get(selector);
  };
  node('#pass').value = DEMO_PASSPHRASE;
  const location = { hash: '#/' };
  const document = {
    querySelector: node,
    querySelectorAll: () => [],
    addEventListener(event, fn) { handlers.set('document:' + event, fn); },
  };
  const window = { addEventListener(event, fn) { handlers.set('window:' + event, fn); }, scrollTo() {}, print() {} };
  let requests = 0;
  let copies = 0;
  const context = {
    document, window, location,
    crypto: webcrypto, TextEncoder, TextDecoder, atob, URLSearchParams,
    navigator: { clipboard: { async writeText() { copies += 1; } } },
    sessionStorage: { getItem: () => null, setItem() {}, removeItem() {} },
    fetch: async url => {
      assert.equal(url, 'data.enc.json', 'Synthetic dashboard must fetch only its encrypted data file');
      requests += 1;
      return { ok: true, json: async () => blob };
    },
  };

  runInNewContext(readFileSync(path.join(staged, 'app.js'), 'utf8'), context);
  const submit = handlers.get('#unlock-form:submit');
  assert.equal(typeof submit, 'function', 'Staged dashboard must register the unlock form');
  await submit({ preventDefault() {} });
  assert.equal(node('#lock').hidden, true, 'Successful example passphrase must close the lock screen');
  assert.equal(node('#app').hidden, false);
  assert.equal(node('#example-banner').hidden, false, 'Fictional records must retain visible example labeling');
  assert.equal(requests, 1);
  assert.match(node('#view').innerHTML, /EXAMPLE|Example/, 'Dashboard should show synthetic campaign');

  location.hash = '#/accounts';
  handlers.get('window:hashchange')();
  const queue = node('#view').innerHTML;
  assert.match(queue, /Example Person|Example Contact/i, 'Fictional contacts must render in queue');
  assert.match(queue, /Snapshot only; verify status before sending/);
  const match = queue.match(/href="#\/contact\/([A-Za-z0-9_-]+)"/);
  assert.ok(match, 'Contact queue must navigate to individual fictional contact');

  location.hash = '#/contact/' + match[1];
  handlers.get('window:hashchange')();
  assert.match(node('#view').innerHTML, /Copy draft|No draft text/);
  assert.equal(copies, 0, 'Viewing a contact must never send or copy outreach automatically');

  handlers.get('#lock-btn:click')();
  assert.equal(node('#lock').hidden, false);
  assert.equal(node('#app').hidden, true);
  assert.equal(node('#view').innerHTML, '', 'Lock must discard the rendered campaign');
  assert.equal(requests, 1, 'Route navigation must not retrieve other sources');
});
