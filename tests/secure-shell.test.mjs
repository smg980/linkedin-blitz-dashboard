import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { isPopupUnavailable, shouldUseRedirectFirst } from '../secure/auth-flow.mjs';
import { assertEmulatorTarget } from '../secure/emulator-guard.mjs';
import { decryptEnvelope, encryptEnvelope, isEnvelope } from '../secure/envelope.mjs';
import { envelopeFromFirestoreFields, privateDocumentUrl, readPrivateDocument } from '../secure/firestore-get.mjs';
import { applyDocumentRead, createSession } from '../secure/session.mjs';
import { syntheticPayload } from '../secure/synthetic-contacts.mjs';
import { wipePrivateRoot } from '../secure/wipe.mjs';
import { buildSecureShell } from '../scripts/build-secure-shell.mjs';
import { FORBIDDEN_SNIPPETS, SECURE_OUT, SECURE_SHELL_FILES, verifySecureShell } from '../scripts/verify-secure-shell.mjs';
import { productionCsp } from '../secure/csp.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const IPHONE = 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1';
const DESKTOP = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';

function fakeRoot(text) {
  const input = { input: true, value: 'secret-passphrase', text: '' };
  const child = { input: false, value: '', text };
  const rootNode = {
    children: [child, input],
    get firstChild() { return this.children[0] || null; },
    removeChild(node) { this.children = this.children.filter((item) => item !== node); },
    querySelectorAll() { return this.children.filter((item) => item.input); },
    get textContent() { return this.children.map((item) => item.text || '').join(''); },
  };
  return { root: rootNode, input };
}

test('iPhone Safari uses redirect first and other browsers start with the popup', () => {
  assert.equal(shouldUseRedirectFirst(IPHONE), true);
  assert.equal(shouldUseRedirectFirst(DESKTOP), false);
  assert.equal(shouldUseRedirectFirst(IPHONE.replace('Safari', 'CriOS')), false);
  assert.equal(isPopupUnavailable({ code: 'auth/popup-blocked' }), true);
  assert.equal(isPopupUnavailable({ code: 'auth/operation-not-supported-in-this-environment' }), true);
  assert.equal(isPopupUnavailable({ code: 'auth/popup-closed-by-user' }), false);
  assert.equal(isPopupUnavailable({ code: 'auth/cancelled-popup-request' }), false);
});

test('state machine and lock wipe drop plaintext', () => {
  const session = createSession();
  assert.equal(session.state(), 'signed-out');
  session.signInStart();
  assert.equal(session.state(), 'signing-in');
  assert.equal(applyDocumentRead(session, { status: 'denied' }), 'not-authorized');
  assert.equal(session.reason(), 'denied');
  assert.equal(session.plaintext(), null);
  assert.equal(applyDocumentRead(session, { status: 'missing' }), 'not-authorized');
  assert.equal(session.reason(), 'missing');
  session.signOut();
  assert.equal(session.state(), 'signed-out');
  session.signInStart();
  session.locked({ v: 1 });
  const secret = { contacts: [{ contact: 'Example Ada' }] };
  session.unlocked(secret);
  assert.equal(session.plaintext(), secret);
  const mounted = fakeRoot('Example Ada');
  session.lock();
  wipePrivateRoot(mounted.root);
  assert.equal(session.state(), 'locked');
  assert.equal(session.plaintext(), null);
  assert.equal(session.ciphertext().v, 1);
  assert.equal(mounted.root.textContent, '');
  assert.equal(mounted.input.value, '');
  session.wrongPassphrase();
  assert.equal(session.state(), 'wrong-passphrase');
  assert.equal(session.plaintext(), null);
  session.signOut();
  assert.equal(session.state(), 'signed-out');
  assert.equal(session.ciphertext(), null);
  assert.throws(() => session.lock(), /Lock requires ciphertext/);
  assert.throws(() => createSession().wrongPassphrase(), /Wrong passphrase requires ciphertext/);
  assert.throws(() => createSession().unlocked(null), /requires plaintext/);
});

test('private document reads are a single get', async () => {
  const calls = [];
  const denied = await readPrivateDocument({
    origin: 'http://127.0.0.1:8080',
    projectId: 'demo-blitz-secure',
    uid: 'owneruid',
    token: 'tok',
  }, async (url, init) => {
    calls.push({ url, method: init.method });
    return { status: 403, ok: false, json: async () => ({}) };
  });
  assert.equal(denied.status, 'denied');
  assert.deepEqual(calls, [{
    url: privateDocumentUrl({ origin: 'http://127.0.0.1:8080', projectId: 'demo-blitz-secure', uid: 'owneruid' }),
    method: 'GET',
  }]);
  assert.equal(calls[0].url.includes('?'), false);
  assert.match(calls[0].url, /\/documents\/blitzOwners\/owneruid\/campaign\/current$/);
  const missing = await readPrivateDocument({
    origin: 'https://firestore.googleapis.com',
    projectId: 'demo-blitz-secure',
    uid: 'owneruid',
    token: 'tok',
  }, async () => ({ status: 404, ok: false, json: async () => ({}) }));
  assert.equal(missing.status, 'missing');
  assert.throws(() => privateDocumentUrl({ origin: 'http://127.0.0.1:8080/extra', projectId: 'demo-blitz-secure', uid: 'abc' }));
  assert.throws(() => privateDocumentUrl({ origin: 'http://127.0.0.1:8080', projectId: 'demo-blitz-secure', uid: 'a/b' }));
});

test('ingestion refuses non-emulator targets', () => {
  assert.throws(() => assertEmulatorTarget({ host: '', projectId: 'demo-blitz-secure' }), /FIRESTORE_EMULATOR_HOST/);
  assert.throws(() => assertEmulatorTarget({ host: 'firestore.googleapis.com:443', projectId: 'demo-blitz-secure' }), /not a local emulator/);
  assert.throws(() => assertEmulatorTarget({ host: '192.168.1.5:8080', projectId: 'demo-blitz-secure' }), /loopback/);
  assert.throws(() => assertEmulatorTarget({ host: '127.0.0.1:8080', projectId: 'master-intelligence-5496f' }), /demo-/);
  assert.deepEqual(assertEmulatorTarget({ host: '127.0.0.1:8080', projectId: 'demo-blitz-secure' }).projectId, 'demo-blitz-secure');
  const env = { ...process.env, FIRESTORE_EMULATOR_HOST: '192.168.1.5:8080', BLITZ_SYNTHETIC_PASSPHRASE: 'synthetic-passphrase-value' };
  delete env.DASHBOARD_PASSPHRASE;
  const refused = spawnSync(process.execPath, [
    path.join(root, 'scripts', 'ingest-synthetic-emulator.mjs'),
    '--project', 'demo-blitz-secure',
    '--uid', 'owneruid',
  ], { cwd: root, env, encoding: 'utf8' });
  assert.notEqual(refused.status, 0);
  assert.match(refused.stderr, /loopback|not a local emulator/);
  const realProject = spawnSync(process.execPath, [
    path.join(root, 'scripts', 'ingest-synthetic-emulator.mjs'),
    '--project', 'master-intelligence-5496f',
    '--uid', 'owneruid',
  ], {
    cwd: root,
    encoding: 'utf8',
    env: { ...env, FIRESTORE_EMULATOR_HOST: '127.0.0.1:9' },
  });
  assert.notEqual(realProject.status, 0);
  assert.match(realProject.stderr, /demo-/);
});

test('shell source is read-only and does not touch web storage', async () => {
  const src = await fs.readFile(path.join(root, 'secure', 'shell.js'), 'utf8');
  assert.match(src, /signInWithPopup/);
  assert.match(src, /signInWithRedirect/);
  assert.match(src, /shouldUseRedirectFirst/);
  assert.match(src, /readPrivateDocument/);
  assert.match(src, /getIdToken\(true\)/);
  const reader = await fs.readFile(path.join(root, 'secure', 'firestore-get.mjs'), 'utf8');
  assert.match(reader, /blitzOwners\/\$\{uid\}\/campaign\/current/);
  assert.doesNotMatch(reader, /linkedinBlitzPrivate/);
  assert.match(await fs.readFile(path.join(root, 'scripts', 'run-secure-suite.mjs'), 'utf8'), /request\.auth\.token\.blitzOwner == true/);
  assert.doesNotMatch(src, /firebase\/firestore|localStorage|sessionStorage|indexedDB|setDoc|updateDoc|addDoc|deleteDoc|writeBatch|getDocs|onSnapshot|collection\(|query\(/);
  const deploy = await fs.readFile(path.join(root, 'scripts', 'deploy-firebase-demo.sh'), 'utf8');
  assert.doesNotMatch(deploy, /firebase\.secure-blitz|private-shell|ingest-synthetic/);
  const ignore = await fs.readFile(path.join(root, '.gitignore'), 'utf8');
  assert.match(ignore, /secure-config\.local\.json/);
  assert.match(ignore, /\.firebase-blitz-private-shell\//);
  const example = JSON.parse(await fs.readFile(path.join(root, 'secure-config.example.json'), 'utf8'));
  assert.match(example.firebase.apiKey, /REPLACE_WITH/);
  assert.match(example.firebase.projectId, /REPLACE_ME/);
  assert.equal(example.useEmulators, false);
  const hosting = JSON.parse(await fs.readFile(path.join(root, 'firebase.secure-blitz.json'), 'utf8'));
  assert.deepEqual(Object.keys(hosting), ['hosting']);
  assert.equal(hosting.hosting.public, '.firebase-blitz-private-shell');
  const csp = hosting.hosting.headers[0].headers.find((item) => item.key === 'Content-Security-Policy').value;
  assert.equal(csp, productionCsp());
  assert.equal(SECURE_SHELL_FILES.includes('data.enc.json'), false);
  assert.ok(FORBIDDEN_SNIPPETS.includes('Example Ada'));
});

test('fictional contacts match the demo builder identities', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'blitz-example-'));
  try {
    const env = { ...process.env, DASHBOARD_PASSPHRASE: 'synthetic-parity-check-pass', BLITZ_OUTPUT_DIR: dir, BLITZ_DIR: path.join(root, 'does-not-exist-private-sources') };
    const result = spawnSync(process.execPath, [path.join(root, 'scripts', 'build.mjs'), '--example', '--plain-check'], {
      cwd: root, env, encoding: 'utf8',
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
    const plain = JSON.parse(await fs.readFile(path.join(dir, 'last.plain.json'), 'utf8'));
    const identity = (rows) => rows.map((row) => `${row.contact}|${row.account}|${row.status}`).sort();
    assert.deepEqual(identity(syntheticPayload().contacts), identity(plain.contacts));
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test('envelope round-trip, wrong passphrase, and secure build contain no ciphertext', async () => {
  const payload = syntheticPayload();
  const passphrase = 'synthetic-shell-passphrase';
  const blob = await encryptEnvelope(payload, passphrase);
  assert.equal(isEnvelope(blob), true);
  assert.deepEqual(await decryptEnvelope(blob, passphrase), payload);
  const again = await encryptEnvelope(payload, passphrase);
  assert.notEqual(blob.salt, again.salt);
  assert.notEqual(blob.iv, again.iv);
  assert.notEqual(blob.ct, again.ct);
  await assert.rejects(() => decryptEnvelope(blob, 'different-passphrase-value'), (error) => error.name === 'OperationError');
  const tampered = { ...blob, ct: blob.ct.slice(0, -2) + (blob.ct.endsWith('a') ? 'b' : 'a') };
  await assert.rejects(() => decryptEnvelope(tampered, passphrase));
  const fields = {
    v: { integerValue: '1' },
    alg: { stringValue: blob.alg },
    kdf: { stringValue: blob.kdf },
    iterations: { integerValue: String(blob.iterations) },
    salt: { stringValue: blob.salt },
    iv: { stringValue: blob.iv },
    ct: { stringValue: blob.ct },
  };
  const session = createSession();
  session.signInStart();
  assert.equal(applyDocumentRead(session, { status: 'ok', envelope: envelopeFromFirestoreFields(fields) }), 'locked');
  const out = await fs.mkdtemp(path.join(os.tmpdir(), 'blitz-secure-shell-'));
  const envPass = process.env.DASHBOARD_PASSPHRASE;
  delete process.env.DASHBOARD_PASSPHRASE;
  try {
    await buildSecureShell({ emulator: true, out });
    const proof = await verifySecureShell(out);
    assert.equal(proof.files, SECURE_SHELL_FILES.length);
    assert.equal(proof.emulator, true);
    const planted = await fs.mkdtemp(path.join(os.tmpdir(), 'blitz-secure-bad-'));
    await fs.cp(out, planted, { recursive: true });
    await fs.writeFile(path.join(planted, 'data.enc.json'), '{}\n');
    await assert.rejects(() => verifySecureShell(planted), /allowlist|forbidden|ciphertext|data\.enc\.json/);
    await fs.rm(path.join(planted, 'data.enc.json'));
    await fs.appendFile(path.join(planted, 'shell.js'), '\n// Example Ada\n');
    await assert.rejects(() => verifySecureShell(planted), /Example Ada/);
    const placeholder = path.join(out, 'placeholder.json');
    await fs.writeFile(placeholder, JSON.stringify({
      firebase: {
        apiKey: 'REPLACE_WITH_FIREBASE_WEB_API_KEY',
        authDomain: 'REPLACE_ME.firebaseapp.com',
        projectId: 'REPLACE_ME',
        appId: 'REPLACE_WITH_FIREBASE_APP_ID',
      },
      useEmulators: false,
    }));
    await assert.rejects(() => buildSecureShell({ emulator: false, configPath: placeholder, out: out + '-prod' }), /placeholder/i);
  } finally {
    if (envPass) process.env.DASHBOARD_PASSPHRASE = envPass;
    await fs.rm(out, { recursive: true, force: true });
  }
});

test('verify:secure-shell builds the emulator shell when output is missing', async () => {
  await fs.rm(SECURE_OUT, { recursive: true, force: true });
  const env = { ...process.env };
  delete env.DASHBOARD_PASSPHRASE;
  const result = spawnSync(process.execPath, [path.join(root, 'scripts', 'verify-secure-shell.mjs')], {
    cwd: root,
    env,
    encoding: 'utf8',
  });
  assert.equal(result.status, 0, result.stderr || result.stdout);
  assert.match(result.stdout, /no campaign ciphertext/);
  const proof = await verifySecureShell(SECURE_OUT);
  assert.equal(proof.files, SECURE_SHELL_FILES.length);
});
