// Step D campaign store: unit tests with in-memory Firestore/Auth fakes and
// synthetic envelopes. No network, no Admin SDK, no real data.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  assertNotPublicBundle,
  assertTarget,
  campaignPath,
  isCredentialEnvKey,
  canonicalEnvelope,
  envelopeDigest,
  ownerEligibility,
  parseEnvelopeText,
  planStoreAction,
  PRODUCTION_PROJECT,
  runStoreAction,
} from '../secure/campaign-store.mjs';
import { outsideRepository, parseArgs, writeBackupFile } from '../scripts/blitz-campaign-store.mjs';
import { encryptEnvelope } from '../secure/envelope.mjs';
import { syntheticPayload } from '../secure/synthetic-contacts.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const UID = 'syntheticOwnerUid01';
const PASS = 'synthetic-store-passphrase';
const envA = await encryptEnvelope(syntheticPayload(), PASS);
const envB = await encryptEnvelope({ ...syntheticPayload(), generatedAt: 'second' }, PASS);
const digestA = envelopeDigest(envA);
const digestB = envelopeDigest(envB);
const publicBundle = parseEnvelopeText(readFileSync(path.join(root, 'docs', 'data.enc.json'), 'utf8'));

function owner(overrides = {}) {
  return {
    uid: UID, email: 'owner-synthetic@example.com', disabled: false, emailVerified: true,
    providerData: [{ providerId: 'google.com' }], customClaims: { blitzOwner: true, other: 'kept' }, ...overrides,
  };
}

function fakeFirebase({ doc = null, user = owner(), beforeTransaction, corruptCommit = false } = {}) {
  let data = doc ? structuredClone(doc) : null;
  const paths = [];
  const writes = [];
  const snapshot = () => ({ exists: data !== null, data: () => structuredClone(data) });
  const ref = { get: async () => snapshot() };
  return {
    paths,
    writes,
    current: () => data,
    auth: { async getUser(uid) { if (!user || uid !== user.uid) throw new Error(`no user ${uid} owner-synthetic@example.com`); return structuredClone(user); } },
    db: {
      doc(p) { paths.push(p); return ref; },
      async runTransaction(fn) {
        if (beforeTransaction) data = beforeTransaction(data);
        const pending = [];
        await fn({
          get: async () => snapshot(),
          create(_ref, value) { if (data !== null) throw new Error('already exists'); pending.push(['create', value]); },
          set(_ref, value) { pending.push(['set', value]); },
          delete() { pending.push(['delete']); },
        });
        for (const [op, value] of pending) {
          writes.push(op);
          data = op === 'delete' ? null : structuredClone(value);
          if (corruptCommit && data) data.ct = envB.ct;
        }
      },
    },
  };
}

function memoryBackup() {
  const files = new Map();
  return { files, write: async (file, envelope) => { files.set(file, structuredClone(envelope)); return envelopeDigest(envelope); } };
}

const emulator = { target: 'emulator' };

test('envelopes are canonical, strict and digest-stable', () => {
  assert.match(digestA, /^[0-9a-f]{64}$/);
  const reordered = Object.fromEntries(Object.entries(envA).reverse());
  assert.equal(envelopeDigest(reordered), digestA);
  assert.deepEqual(Object.keys(canonicalEnvelope(reordered)), ['v', 'alg', 'kdf', 'iterations', 'salt', 'iv', 'ct']);
  assert.notEqual(digestA, digestB);
  for (const bad of [
    null, [], 'x', { ...envA, extra: 1 }, { ...envA, ct: undefined },
    (({ ct, ...rest }) => rest)(envA), { ...envA, iterations: 100000 }, { ...envA, v: 2 },
    { ...envA, alg: 'AES-128-GCM' }, { ...envA, ct: `${envA.ct.slice(0, 8)} ${envA.ct.slice(8)}` },
    { ...envA, salt: `${envA.salt}\n` }, { ...envA, iv: 'AAAA' }, { ...envA, ct: 'AAAA' },
  ]) {
    assert.throws(() => canonicalEnvelope(bad), (e) => /^STORE_/.test(e.code), JSON.stringify(bad)?.slice(0, 60));
  }
  assert.throws(() => parseEnvelopeText('{not json'), { code: 'STORE_NOT_JSON' });
  assert.throws(() => canonicalEnvelope({ ...envA, ct: 'A'.repeat(1_000_004) }), { code: 'STORE_ENVELOPE_TOO_LARGE' });
});

test('the public GitHub Pages bundle, or anything sharing its key material, is refused', () => {
  assert.throws(() => assertNotPublicBundle(publicBundle, publicBundle), { code: 'STORE_PUBLIC_BUNDLE_REFUSED' });
  for (const key of ['salt', 'iv', 'ct']) {
    assert.throws(() => assertNotPublicBundle({ ...envA, [key]: publicBundle[key] }, publicBundle), { code: 'STORE_PUBLIC_BUNDLE_REFUSED' });
  }
  assert.doesNotThrow(() => assertNotPublicBundle(envA, publicBundle));
});

test('targets: emulator must be demo- on loopback; production must be exact, local, keyless and passphrase-free', () => {
  const loop = { FIRESTORE_EMULATOR_HOST: '127.0.0.1:8080', FIREBASE_AUTH_EMULATOR_HOST: '127.0.0.1:9099' };
  assert.deepEqual(assertTarget({ target: 'emulator', projectId: 'demo-blitz-store', env: loop }), { target: 'emulator', projectId: 'demo-blitz-store' });
  assert.deepEqual(assertTarget({ target: 'production', projectId: PRODUCTION_PROJECT, env: {} }), { target: 'production', projectId: PRODUCTION_PROJECT });
  const refusals = [
    ['emulator', PRODUCTION_PROJECT, loop, 'STORE_EMULATOR_PROJECT'],
    ['emulator', `demo-${PRODUCTION_PROJECT}`, loop, 'STORE_EMULATOR_PROJECT'],
    ['emulator', 'demo-blitz-store', { ...loop, FIRESTORE_EMULATOR_HOST: 'firestore.googleapis.com:443' }, 'STORE_LOOPBACK_FIRESTORE_REQUIRED'],
    ['emulator', 'demo-blitz-store', { FIRESTORE_EMULATOR_HOST: '127.0.0.1:8080' }, 'STORE_LOOPBACK_AUTH_REQUIRED'],
    ['emulator', 'demo-blitz-store', { ...loop, GOOGLE_APPLICATION_CREDENTIALS: '/k.json' }, 'STORE_CREDENTIAL_ENV_REFUSED'],
    ['production', 'master-intelligence-5496f-lb', {}, 'STORE_PRODUCTION_PROJECT'],
    ['production', PRODUCTION_PROJECT, { CI: 'true' }, 'STORE_NEVER_FROM_CI'],
    ['production', PRODUCTION_PROJECT, { GITHUB_ACTIONS: 'true' }, 'STORE_NEVER_FROM_CI'],
    ['production', PRODUCTION_PROJECT, { FIRESTORE_EMULATOR_HOST: '127.0.0.1:8080' }, 'STORE_EMULATOR_ENV_WITH_PRODUCTION'],
    ['production', PRODUCTION_PROJECT, { GOOGLE_APPLICATION_CREDENTIALS: '/k.json' }, 'STORE_KEY_FILE_REFUSED'],
    ['production', PRODUCTION_PROJECT, { FIREBASE_TOKEN: 'x' }, 'STORE_KEY_FILE_REFUSED'],
    ['production', PRODUCTION_PROJECT, { DASHBOARD_PASSPHRASE: 'x' }, 'STORE_PASSPHRASE_IN_ENV'],
    ['production', PRODUCTION_PROJECT, { BLITZ_NEW_PASSPHRASE: 'x' }, 'STORE_PASSPHRASE_IN_ENV'],
    ['staging', PRODUCTION_PROJECT, {}, 'STORE_INVALID_TARGET'],
    [undefined, PRODUCTION_PROJECT, {}, 'STORE_INVALID_TARGET'],
  ];
  for (const [target, projectId, env, code] of refusals) {
    assert.throws(() => assertTarget({ target, projectId, env }), { code }, `${target} ${projectId} ${JSON.stringify(env)}`);
  }
});

test('owner eligibility needs every check, with a strict boolean claim', () => {
  assert.equal(ownerEligibility(owner(), UID).eligible, true);
  for (const overrides of [{ disabled: true }, { disabled: undefined }, { emailVerified: false }, { providerData: [] },
    { providerData: [{ providerId: 'password' }] }, { customClaims: {} }, { customClaims: { blitzOwner: 'true' } },
    { customClaims: { blitzOwner: 1 } }, { customClaims: null }, { uid: 'someoneElse' }]) {
    assert.equal(ownerEligibility(owner(overrides), UID).eligible, false, JSON.stringify(overrides));
  }
});

test('plans are dry runs; apply needs exact uid, digest-bound approval, CAS value, and a backup when replacing', () => {
  const base = { ...emulator, uid: UID, user: owner() };
  const inspect = planStoreAction({ ...base, action: 'inspect', current: envA });
  assert.deepEqual(inspect, { action: 'inspect', ownerEligible: true, documentExists: true, currentDigest: digestA, requiredExpectCurrent: digestA });
  assert.throws(() => planStoreAction({ ...base, action: 'inspect', apply: true }), { code: 'STORE_INSPECT_IS_READ_ONLY' });

  const dry = planStoreAction({ ...base, action: 'write', current: null, input: envA });
  assert.equal(dry.requiredApproval, `WRITE:${digestA}`);
  assert.equal(dry.requiredExpectCurrent, 'none');
  const good = { ...base, action: 'write', current: null, input: envA, apply: true, confirmUid: UID, approval: `WRITE:${digestA}`, expectCurrent: 'none', receiptPath: '/private/r.json' };
  assert.equal(planStoreAction(good).inputDigest, digestA);
  const refusals = [
    [{ confirmUid: undefined }, 'STORE_EXACT_UID_CONFIRMATION_REQUIRED'],
    [{ confirmUid: 'syntheticOwnerUid02' }, 'STORE_EXACT_UID_CONFIRMATION_REQUIRED'],
    [{ approval: undefined }, 'STORE_APPROVAL_REQUIRED'],
    [{ approval: 'YES' }, 'STORE_APPROVAL_REQUIRED'],
    [{ approval: `WRITE:${digestB}` }, 'STORE_APPROVAL_REQUIRED'],
    [{ approval: `RETRACT:${digestA}` }, 'STORE_APPROVAL_REQUIRED'],
    [{ expectCurrent: undefined }, 'STORE_EXPECT_CURRENT_REQUIRED'],
    [{ expectCurrent: digestB }, 'STORE_CURRENT_MISMATCH'],
    [{ input: undefined }, 'STORE_INPUT_REQUIRED'],
    [{ user: owner({ customClaims: {} }) }, 'STORE_OWNER_NOT_ELIGIBLE'],
    [{ user: owner({ disabled: true }) }, 'STORE_OWNER_NOT_ELIGIBLE'],
    [{ user: owner({ email: 'someone@gmail.com' }) }, 'STORE_SYNTHETIC_ACCOUNT_REQUIRED'],
    [{ user: owner({ uid: 'other' }) }, 'STORE_UNKNOWN_UID'],
    [{ uid: '../x', confirmUid: '../x' }, 'STORE_INVALID_UID'],
    [{ action: 'delete' }, 'STORE_INVALID_ACTION'],
    [{ apply: 'yes' }, 'STORE_INVALID_APPLY'],
    [{ receiptPath: undefined }, 'STORE_RECEIPT_REQUIRED'],
    [{ receiptPath: '' }, 'STORE_RECEIPT_REQUIRED'],
  ];
  for (const [overrides, code] of refusals) {
    assert.throws(() => planStoreAction({ ...good, ...overrides }), { code }, JSON.stringify(overrides));
  }
  // Replacing an existing document: CAS on its digest and a backup are required.
  const replace = { ...good, current: envA, input: envB, approval: `WRITE:${digestB}`, expectCurrent: digestA, backupPath: '/tmp/b.json' };
  assert.equal(planStoreAction(replace).currentDigest, digestA);
  assert.throws(() => planStoreAction({ ...replace, backupPath: undefined }), { code: 'STORE_BACKUP_REQUIRED' });
  assert.throws(() => planStoreAction({ ...replace, expectCurrent: 'none' }), { code: 'STORE_CURRENT_MISMATCH' });
  assert.throws(() => planStoreAction({ ...replace, input: envA, approval: `WRITE:${digestA}` }), { code: 'STORE_ALREADY_CURRENT' });
  // Retract is allowed for a revoked owner but still needs approval, CAS and backup.
  const retract = { ...base, action: 'retract', current: envA, apply: true, confirmUid: UID, approval: `RETRACT:${digestA}`, expectCurrent: digestA, backupPath: '/tmp/b.json', receiptPath: '/private/r.json', user: owner({ customClaims: {}, disabled: true }) };
  assert.equal(planStoreAction(retract).requiredApproval, `RETRACT:${digestA}`);
  assert.throws(() => planStoreAction({ ...retract, current: null, expectCurrent: 'none' }), { code: 'STORE_NOTHING_TO_RETRACT' });
  assert.throws(() => planStoreAction({ ...retract, approval: `WRITE:${digestA}` }), { code: 'STORE_APPROVAL_REQUIRED' });
  assert.throws(() => planStoreAction({ ...retract, backupPath: '' }), { code: 'STORE_BACKUP_REQUIRED' });
});

function memoryReceipt() {
  const files = new Map();
  return {
    files,
    create: async (file, body) => { if (files.has(file)) throw new Error('EEXIST'); files.set(file, structuredClone(body)); },
    update: async (file, body) => { files.set(file, structuredClone(body)); },
  };
}

let receiptCount = 0;
function approvedWrite(fake, extra = {}) {
  receiptCount += 1;
  return {
    db: fake.db, auth: fake.auth, backup: memoryBackup(), receipt: memoryReceipt(), receiptPath: `/private/receipt-${receiptCount}.json`,
    target: 'emulator', action: 'write', uid: UID,
    confirmUid: UID, approval: `WRITE:${digestA}`, input: envA, expectCurrent: 'none', apply: true, ...extra,
  };
}

test('write, replace with backup, retract and restore round-trip through the exact document path', async () => {
  const fake = fakeFirebase();
  const dry = await runStoreAction({ ...approvedWrite(fake), apply: false });
  assert.equal(dry.dryRun, true);
  assert.equal(fake.current(), null);
  assert.deepEqual(fake.writes, []);

  const created = await runStoreAction(approvedWrite(fake));
  assert.deepEqual(fake.paths.at(-1), `blitzOwners/${UID}/campaign/current`);
  assert.deepEqual(fake.writes, ['create']);
  assert.equal(created.liveDigest, digestA);
  assert.equal(created.outcome, 'committed-verified');
  assert.deepEqual(created.rollback, { action: 'retract', expectCurrent: digestA, approval: `RETRACT:${digestA}`, backupRequired: true });
  assert.equal(envelopeDigest(fake.current()), digestA);

  const backup = memoryBackup();
  const replaced = await runStoreAction(approvedWrite(fake, { backup, input: envB, approval: `WRITE:${digestB}`, expectCurrent: digestA, backupPath: '/b1' }));
  assert.equal(envelopeDigest(backup.files.get('/b1')), digestA);
  assert.equal(replaced.previousDigest, digestA);
  assert.equal(replaced.backupWritten, true);
  assert.deepEqual(replaced.rollback, { action: 'write', input: '/b1', inputDigest: digestA, expectCurrent: digestB, approval: `WRITE:${digestA}`, backupRequired: true });

  const backup2 = memoryBackup();
  const retracted = await runStoreAction(approvedWrite(fake, { backup: backup2, action: 'retract', input: null, approval: `RETRACT:${digestB}`, expectCurrent: digestB, backupPath: '/b2' }));
  assert.equal(fake.current(), null);
  assert.equal(retracted.liveDigest, null);
  assert.deepEqual(retracted.rollback, { action: 'write', input: '/b2', inputDigest: digestB, expectCurrent: 'none', approval: `WRITE:${digestB}`, backupRequired: false });

  // Restore exactly what was retracted, from its backup.
  await runStoreAction(approvedWrite(fake, { input: backup2.files.get('/b2'), approval: `WRITE:${digestB}`, expectCurrent: 'none' }));
  assert.equal(envelopeDigest(fake.current()), digestB);
  assert.deepEqual(fake.writes, ['create', 'set', 'delete', 'create']);
});

test('a concurrent change, failed readback, bad backup or foreign document stops without a silent write', async () => {
  const raced = fakeFirebase({ beforeTransaction: () => structuredClone(envB) });
  await assert.rejects(runStoreAction(approvedWrite(raced)), { code: 'STORE_CONCURRENT_CHANGE' });
  assert.deepEqual(raced.writes, []);
  assert.equal(envelopeDigest(raced.current()), digestB);

  // A commit that reads back as something else is an unknown outcome, never "verified".
  const corrupt = fakeFirebase({ corruptCommit: true });
  await assert.rejects(runStoreAction(approvedWrite(corrupt)), { code: 'STORE_OUTCOME_UNKNOWN' });

  const existing = fakeFirebase({ doc: envA });
  const lying = { write: async () => digestB };
  await assert.rejects(runStoreAction(approvedWrite(existing, { backup: lying, input: envB, approval: `WRITE:${digestB}`, expectCurrent: digestA, backupPath: '/b' })),
    { code: 'STORE_BACKUP_VERIFICATION_FAILED' });
  assert.deepEqual(existing.writes, []);

  const foreign = fakeFirebase({ doc: { hello: 'world' } });
  await assert.rejects(runStoreAction(approvedWrite(foreign)), { code: 'STORE_CURRENT_NOT_ENVELOPE' });
  assert.deepEqual(foreign.writes, []);

  const missing = fakeFirebase({ user: null });
  await assert.rejects(runStoreAction(approvedWrite(missing)), (error) => error.code === 'STORE_UNKNOWN_UID' && !/example\.com|syntheticOwner/.test(error.message));

  const unclaimed = fakeFirebase({ user: owner({ customClaims: {} }) });
  await assert.rejects(runStoreAction(approvedWrite(unclaimed)), { code: 'STORE_OWNER_NOT_ELIGIBLE' });
  assert.deepEqual(unclaimed.writes, []);
});

test('CLI arguments are strict, inspect is read-only, and identity never comes from argv', () => {
  assert.deepEqual(parseArgs(['inspect', '--target', 'emulator', '--project', 'demo-x']), { action: 'inspect', apply: false, target: 'emulator', project: 'demo-x' });
  assert.equal(parseArgs(['write', '--input', '/x', '--expect-current', 'none', '--apply']).expectCurrent, 'none');
  for (const argv of [[], ['delete'], ['inspect', '--uid', 'x'], ['inspect', '--target'], ['inspect', '--target', '--apply'],
    ['inspect', '--apply'], ['inspect', '--backup', '/b'], ['retract', '--input', '/x'], ['write', '--apply', '--apply'],
    ['write', '--target', 'emulator', '--target', 'production']]) {
    assert.throws(() => parseArgs(argv), (e) => /^STORE_/.test(e.code), JSON.stringify(argv));
  }
});

test('paths inside the repository are refused for inputs and backups', () => {
  assert.throws(() => outsideRepository(root, 'X', root), { code: 'X' });
  assert.throws(() => outsideRepository(path.join(root, 'docs', 'x.json'), 'X', root), { code: 'X' });
  assert.equal(outsideRepository(`${root}-sibling/x.json`, 'X', root), `${root}-sibling/x.json`);
  assert.equal(outsideRepository('/tmp/x.json', 'X', root), '/tmp/x.json');
});

test('backup files are exclusive, mode 600, and verified by re-reading', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'blitz-store-backup-'));
  try {
    const file = path.join(dir, 'backup.json');
    assert.equal(await writeBackupFile(file, envA), digestA);
    assert.equal((await fs.stat(file)).mode & 0o777, 0o600);
    await assert.rejects(writeBackupFile(file, envB), /EEXIST/);
    assert.equal(envelopeDigest(parseEnvelopeText(await fs.readFile(file, 'utf8'))), digestA);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

function cli(args, env) {
  const clean = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (/^(BLITZ_|FIRESTORE_EMULATOR_HOST|FIREBASE_AUTH_EMULATOR_HOST|CI$|GITHUB_ACTIONS)|PASSPHRASE/i.test(key) || isCredentialEnvKey(key)) continue;
    clean[key] = value;
  }
  return spawnSync(process.execPath, ['scripts/blitz-campaign-store.mjs', ...args], {
    cwd: root, encoding: 'utf8', timeout: 20000, env: { ...clean, ...env },
  });
}

test('CLI refuses before loading the Admin SDK and prints only fixed codes', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'blitz-store-cli-'));
  try {
    const synthetic = path.join(dir, 'synthetic.json');
    await fs.writeFile(synthetic, JSON.stringify(envA));
    const publicCopy = path.join(dir, 'public-copy.json');
    await fs.copyFile(path.join(root, 'docs', 'data.enc.json'), publicCopy);
    const insideRepo = path.join(root, 'docs', 'data.enc.json');
    const secretUid = 'privateLookingUid999';
    // Port 9 is discard; any SDK call would fail differently from these fixed codes.
    const loop = { FIRESTORE_EMULATOR_HOST: '127.0.0.1:9', FIREBASE_AUTH_EMULATOR_HOST: '127.0.0.1:9', BLITZ_STORE_UID: secretUid };
    const emu = ['--target', 'emulator', '--project', 'demo-blitz-store'];
    const cases = [
      [['write', '--target', 'production', '--project', PRODUCTION_PROJECT, '--input', synthetic], { CI: 'true', BLITZ_STORE_UID: secretUid }, 'STORE_NEVER_FROM_CI'],
      [['inspect', '--target', 'production', '--project', PRODUCTION_PROJECT], { CI: 'true', BLITZ_STORE_UID: secretUid }, 'STORE_NEVER_FROM_CI'],
      [['inspect', '--target', 'production', '--project', PRODUCTION_PROJECT], { ...loop }, 'STORE_EMULATOR_ENV_WITH_PRODUCTION'],
      [['inspect', '--target', 'production', '--project', 'demo-blitz-store'], { BLITZ_STORE_UID: secretUid, CI: 'true' }, 'STORE_PRODUCTION_PROJECT'],
      [['inspect', ...emu], { ...loop, DASHBOARD_PASSPHRASE: 'x' }, 'STORE_PASSPHRASE_IN_ENV'],
      [['inspect', ...emu], { ...loop, BLITZ_STORE_UID: '../etc' }, 'STORE_INVALID_UID'],
      [['write', ...emu, '--input', insideRepo], loop, 'STORE_INPUT_INSIDE_REPOSITORY'],
      [['write', ...emu, '--input', publicCopy], loop, 'STORE_PUBLIC_BUNDLE_REFUSED'],
      [['write', ...emu, '--input', path.join(dir, 'missing.json')], loop, 'STORE_INPUT_UNREADABLE'],
      [['write', ...emu], loop, 'STORE_INPUT_REQUIRED'],
      [['write', ...emu, '--input', synthetic, '--backup', path.join(root, 'backup.json'), '--apply'], loop, 'STORE_BACKUP_INSIDE_REPOSITORY'],
      [['write', ...emu, '--input', synthetic, '--backup', synthetic, '--apply'], loop, 'STORE_BACKUP_EXISTS'],
      [['write', ...emu, '--input', synthetic, '--backup', path.join(dir, 'nodir', 'b.json'), '--apply'], loop, 'STORE_BACKUP_DIRECTORY_MISSING'],
    ];
    for (const [args, env, code] of cases) {
      const result = cli(args, env);
      assert.equal(result.status, 1, `${code}: ${result.stdout}${result.stderr}`);
      assert.equal(result.stderr.trim(), `STORE_REFUSED ${code}`, args.join(' '));
      assert.equal(result.stdout, '');
      assert.doesNotMatch(result.stdout + result.stderr, new RegExp(secretUid));
    }
    // Nothing was created by any refusal.
    assert.deepEqual((await fs.readdir(dir)).sort(), ['public-copy.json', 'synthetic.json']);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test('campaign path is the one owner document the client reads', () => {
  assert.equal(campaignPath(UID), `blitzOwners/${UID}/campaign/current`);
  const reader = readFileSync(path.join(root, 'secure', 'firestore-get.mjs'), 'utf8');
  assert.match(reader, /blitzOwners\/\$\{uid\}\/campaign\/current/);
  for (const bad of ['', 'a/b', 'a b', '..', 'x'.repeat(129), null]) assert.throws(() => campaignPath(bad), { code: 'STORE_INVALID_UID' });
});

test('store suite runner needs a recorded zero exit and exactly one complete 3/3 summary', async () => {
  const { storeSuiteFailure, EXPECTED_TESTS } = await import('../scripts/run-campaign-store-suite.mjs');
  assert.equal(EXPECTED_TESTS, 3);
  const summary = (t, p, f = 0, extra = '') => `ℹ tests ${t}\nℹ pass ${p}\nℹ fail ${f}\nℹ cancelled 0\nℹ skipped 0\nℹ todo 0\n${extra}`;
  const ok = { execCode: 0, execSignal: null, childStatus: 0, timedOut: false, survivors: [], output: summary(3, 3) };
  assert.equal(storeSuiteFailure(ok), null);
  assert.equal(storeSuiteFailure({ ...ok, output: `\u001b[34mℹ\u001b[39m tests 3\n${summary(3, 3).split('\n').slice(1).join('\n')}` }), null);
  for (const bad of [
    { output: summary(2, 2) }, { output: summary(3, 2, 1) }, { output: '' }, { output: summary(3, 3) + summary(3, 3) },
    { output: summary(3, 3, 0, '✖ something failed') }, { childStatus: null }, { childStatus: 1 }, { execCode: 1 },
    { execCode: null, execSignal: 'SIGKILL' }, { timedOut: true }, { survivors: ['123'] },
  ]) {
    assert.notEqual(storeSuiteFailure({ ...ok, ...bad }), null, JSON.stringify(bad));
  }
});
