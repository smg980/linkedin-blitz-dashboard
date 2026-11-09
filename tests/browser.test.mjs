import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { webcrypto } from 'node:crypto';
import { runInNewContext } from 'node:vm';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = fileURLToPath(new URL('../', import.meta.url));
const statuses = ['Research Needed', 'Draft Ready', 'Approved', 'Sent Confirmed', 'Replied', 'Next Action', 'On Hold'];
const old = {
  id: 'old', personKey: 'ACME-JANE', account: 'Acme', contact: 'Jane Example', role: 'CTO',
  status: 'Sent Confirmed', statusRaw: 'Sent Confirmed', due: '2026-11-08', dueIso: '2026-11-08',
  action: 'Connection note', actionCode: 'CONNECT', draft: 'v1', connectionNote: 'Previously sent',
  nextAction: 'Completed', key: 'ACME-JANE-20261108-CONNECT'
};
const next = {
  ...old, id: 'next', status: 'Draft Ready', statusRaw: 'Draft Ready', due: '2026-11-10', dueIso: '2026-11-10',
  action: 'After-accept message', actionCode: 'AFTERACCEPT', draft: 'v2', connectionNote: '',
  followup: 'Hello <img src=x onerror=alert(1)>', nextAction: 'Send after approval',
  key: 'ACME-JANE-20261110-AFTERACCEPT'
};
const payload = {
  generatedAt: '2026-11-09T16:00:00Z', example: true,
  campaign: { name: 'Synthetic', start: '2026-11-08', end: '2026-11-11', accounts: ['Acme'], rules: [], plan: {} },
  contacts: [old, next], briefs: [], plans: [], needs: [], schedule: [],
  statuses, recap: Object.fromEntries(statuses.map(s => [s, [old, next].filter(r => r.status === s).length]))
};

async function encryptedData(data, passphrase) {
  const salt = webcrypto.getRandomValues(new Uint8Array(16));
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const base = await webcrypto.subtle.importKey('raw', new TextEncoder().encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  const key = await webcrypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
  const ct = await webcrypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(JSON.stringify(data)));
  return { v: 1, alg: 'AES-256-GCM', kdf: 'PBKDF2-SHA256', iterations: 600000,
    salt: Buffer.from(salt).toString('base64'), iv: Buffer.from(iv).toString('base64'),
    ct: Buffer.from(ct).toString('base64') };
}

test('browser queue shows the next pending touch and copies only after a direct click', async () => {
  const passphrase = 'synthetic-browser-test';
  const blob = await encryptedData(payload, passphrase);
  const nodes = new Map(), handlers = {};
  const node = selector => {
    if (!nodes.has(selector)) nodes.set(selector, { innerHTML: '', textContent: '', hidden: false, value: '', checked: false, disabled: false, className: '', focus() {},
      addEventListener(event, fn) { handlers[selector + ':' + event] = fn; } });
    return nodes.get(selector);
  };
  node('#pass').value = passphrase;
  let copied = null, fetchCount = 0;
  const location = { hash: '#/accounts' };
  const document = {
    querySelector: node,
    querySelectorAll: () => [],
    addEventListener: (event, fn) => { handlers[event] = fn; }
  };
  const window = {
    addEventListener: (event, fn) => { handlers[event] = fn; },
    scrollTo() {}, print() {}
  };
  const sessionStorage = { getItem: () => null, setItem() {}, removeItem() {} };
  const navigator = { clipboard: { async writeText(value) { copied = value; } } };
  const context = {
    document, window, location, sessionStorage, navigator,
    crypto: webcrypto, TextEncoder, TextDecoder, atob,
    fetch: async () => { fetchCount++; return { ok: true, json: async () => blob }; }
  };
  runInNewContext(readFileSync(path.join(root, 'docs', 'app.js'), 'utf8'), context);
  const submit = handlers['#unlock-form:submit'];
  assert.equal(typeof submit, 'function');
  await submit({ preventDefault() {} });
  assert.equal(node('#lock').hidden, true);
  assert.equal(node('#app').hidden, false);
  assert.equal(fetchCount, 1);
  assert.match(node('#view').innerHTML, /2026-11-10/);
  assert.doesNotMatch(node('#view').innerHTML, /2026-11-08/);

  location.hash = '#/contact/old';
  handlers.hashchange();
  assert.match(node('#view').innerHTML, /data-copy-draft="next"/);
  assert.doesNotMatch(node('#view').innerHTML, /<img src=x onerror/);
  const btn = { dataset: { copyDraft: 'next' }, textContent: 'Copy draft' };
  assert.equal(copied, null);
  await handlers.click({ target: {
    closest(selector) { return selector === '[data-copy-draft]' ? btn : null; }
  } });
  assert.equal(copied, 'Hello <img src=x onerror=alert(1)>');
  assert.equal(btn.textContent, 'Copied');
});
