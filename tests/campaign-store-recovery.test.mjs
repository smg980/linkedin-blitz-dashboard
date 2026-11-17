// F4/F5/F6 and the Auth claim-change race for the Step D store. In-memory
// Firestore/Auth fakes, fictional envelopes, temporary directories only.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { assertTarget, envelopeDigest, isCredentialEnvKey, PRODUCTION_PROJECT, runStoreAction } from '../secure/campaign-store.mjs';
import { main, outsideRepository } from '../scripts/blitz-campaign-store.mjs';
import { encryptEnvelope } from '../secure/envelope.mjs';
import { syntheticPayload } from '../secure/synthetic-contacts.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const UID = 'syntheticOwnerUid01';
const PASS = 'synthetic-recovery-passphrase';
const envA = await encryptEnvelope(syntheticPayload(), PASS);
const envB = await encryptEnvelope({ ...syntheticPayload(), generatedAt: 'second' }, PASS);
const envC = await encryptEnvelope({ ...syntheticPayload(), generatedAt: 'third' }, PASS);
const digestA = envelopeDigest(envA);
const digestB = envelopeDigest(envB);
const digestC = envelopeDigest(envC);

function owner(overrides = {}) {
  return {
    uid: UID, email: 'owner-synthetic@example.com', disabled: false, emailVerified: true,
    providerData: [{ providerId: 'google.com' }], customClaims: { blitzOwner: true, other: 'kept' },
    tokensValidAfterTime: 'Sun, 15 Nov 2026 00:00:00 GMT', ...overrides,
  };
}

const unavailable = () => Object.assign(new Error('14 UNAVAILABLE: synthetic lost acknowledgement'), { code: 14 });

// A Firestore fake that behaves like the Admin SDK where it matters here: a
// callback error rolls back; a retryable commit error is retried unless
// maxAttempts is 1; and a commit can apply and then lose its acknowledgement.
function fakeFirebase({ doc = null, users = [owner()], afterCommit, commitFault, readbackFault, inTransaction } = {}) {
  let data = doc ? structuredClone(doc) : null;
  let userCalls = 0;
  const commits = [];
  const callbacks = [];
  const snapshot = () => ({ exists: data !== null, data: () => structuredClone(data) });
  let gets = 0;
  return {
    commits,
    callbacks,
    current: () => data,
    userCalls: () => userCalls,
    auth: {
      async getUser(uid) {
        const user = users[Math.min(userCalls, users.length - 1)];
        userCalls += 1;
        if (!user || uid !== user.uid) throw new Error('no such synthetic user');
        return structuredClone(user);
      },
    },
    db: {
      doc() {
        return {
          get: async () => {
            gets += 1;
            if (readbackFault && gets > 1) return readbackFault(snapshot);
            return snapshot();
          },
        };
      },
      async runTransaction(fn, options = {}) {
        const attempts = options.maxAttempts ?? 5;
        let lastError;
        for (let attempt = 0; attempt < attempts; attempt++) {
          callbacks.push(attempt);
          const pending = [];
          await fn({
            get: async () => snapshot(),
            create(_ref, value) { if (data !== null) throw new Error('already exists'); pending.push(['create', value]); },
            set(_ref, value) { pending.push(['set', value]); },
            delete() { pending.push(['delete']); },
          });
          if (inTransaction) inTransaction();
          for (const [op, value] of pending) {
            commits.push(op);
            data = op === 'delete' ? null : structuredClone(value);
          }
          if (afterCommit) data = afterCommit(data);
          if (commitFault) {
            lastError = commitFault();
            if (lastError) continue; // the SDK treats UNAVAILABLE as retryable
          }
          return;
        }
        throw lastError;
      },
    },
  };
}

function memoryBackup({ fail = false } = {}) {
  const files = new Map();
  return {
    files,
    write: async (file, envelope) => {
      if (fail) throw new Error('disk full (synthetic)');
      files.set(file, structuredClone(envelope));
      return envelopeDigest(envelope);
    },
  };
}

function memoryReceipts() {
  const log = [];
  const files = new Map();
  return {
    log,
    files,
    latest: (file) => files.get(file),
    create: async (file, body) => {
      if (files.has(file)) throw new Error('EEXIST');
      files.set(file, structuredClone(body));
      log.push(['create', body.status]);
    },
    update: async (file, body) => {
      files.set(file, structuredClone(body));
      log.push(['update', body.status]);
    },
  };
}

function apply(fake, extra = {}) {
  return {
    db: fake.db, auth: fake.auth, backup: memoryBackup(), receipt: memoryReceipts(), receiptPath: '/private/receipt.json',
    target: 'emulator', action: 'write', uid: UID, confirmUid: UID, approval: `WRITE:${digestA}`, input: envA,
    expectCurrent: 'none', apply: true, ...extra,
  };
}

// ---------------------------------------------------------------- F4

test('F4: both spellings of GOOGLE_APPLICATION_CREDENTIALS, and other credential overrides, are refused', () => {
  const loop = { FIRESTORE_EMULATOR_HOST: '127.0.0.1:8080', FIREBASE_AUTH_EMULATOR_HOST: '127.0.0.1:9099' };
  for (const name of ['GOOGLE_APPLICATION_CREDENTIALS', 'google_application_credentials', 'Google_Application_Credentials']) {
    assert.throws(() => assertTarget({ target: 'production', projectId: PRODUCTION_PROJECT, env: { [name]: '/k.json' } }), { code: 'STORE_KEY_FILE_REFUSED' }, name);
    assert.throws(() => assertTarget({ target: 'emulator', projectId: 'demo-blitz-store', env: { ...loop, [name]: '/k.json' } }), { code: 'STORE_CREDENTIAL_ENV_REFUSED' }, name);
    // Present but empty is still refused: never depend on how a library treats it.
    assert.throws(() => assertTarget({ target: 'production', projectId: PRODUCTION_PROJECT, env: { [name]: '' } }), { code: 'STORE_KEY_FILE_REFUSED' }, `${name} empty`);
  }
  for (const name of ['firebase_token', 'CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE', 'CLOUDSDK_AUTH_ACCESS_TOKEN_FILE', 'GOOGLE_OAUTH_ACCESS_TOKEN']) {
    assert.throws(() => assertTarget({ target: 'production', projectId: PRODUCTION_PROJECT, env: { [name]: 'x' } }), { code: 'STORE_KEY_FILE_REFUSED' }, name);
  }
});

test('F4: the production CLI never asks the SDK for generic Application Default Credentials', async () => {
  const source = await fs.readFile(path.join(root, 'scripts', 'blitz-campaign-store.mjs'), 'utf8');
  assert.doesNotMatch(source, /applicationDefault\s*\(/);
});

// ---------------------------------------------------------------- F5

test('F5: repository boundary uses path segments, not a string prefix', () => {
  const inside = [
    root,
    path.join(root, 'docs', 'x.json'),
    path.join(root, '..private', 'campaign.json'),
    path.join(root, '..backup.json'),
    path.join(root, '...json'),
    path.join(root, '..', path.basename(root), 'x.json'),
  ];
  for (const file of inside) assert.throws(() => outsideRepository(path.resolve(file), 'X', root), { code: 'X' }, file);
  const outside = [
    path.dirname(root),
    `${root}-sibling/x.json`,
    `${root}2/x.json`,
    path.join(path.dirname(root), '..private', 'x.json'),
    '/tmp/x.json',
  ];
  for (const file of outside) assert.equal(outsideRepository(file, 'X', root), file, file);
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

test('F5: inputs and backups inside the repository are refused through ..names, siblings and symlinks', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'blitz-store-boundary-'));
  const planted = [];
  try {
    const synthetic = path.join(dir, 'synthetic.json');
    await fs.writeFile(synthetic, JSON.stringify(envA));
    const loop = { FIRESTORE_EMULATOR_HOST: '127.0.0.1:9', FIREBASE_AUTH_EMULATOR_HOST: '127.0.0.1:9', BLITZ_STORE_UID: UID };
    const emu = ['--target', 'emulator', '--project', 'demo-blitz-store'];
    // Fictional envelopes planted inside the checkout under names that defeat a prefix test.
    for (const rel of ['..private/campaign.json', '..campaign.json']) {
      const file = path.join(root, rel);
      await fs.mkdir(path.dirname(file), { recursive: true });
      await fs.writeFile(file, JSON.stringify(envB));
      planted.push(file);
    }
    const linkToRepo = path.join(dir, 'repo-link');
    await fs.symlink(root, linkToRepo, 'dir');
    const linkToRepoFile = path.join(dir, 'campaign-link.json');
    await fs.symlink(path.join(root, '..campaign.json'), linkToRepoFile);
    const linkToDocs = path.join(dir, 'docs-link');
    await fs.symlink(path.join(root, 'docs'), linkToDocs, 'dir');
    // Apply path checks run inside the trusted worker; exercise that private
    // entry point without installing an OS service for these early refusals.
    const cases = [
      [['write', ...emu, '--input', path.join(root, '..private', 'campaign.json')], 'STORE_INPUT_INSIDE_REPOSITORY'],
      [['write', ...emu, '--input', path.join(root, '..campaign.json')], 'STORE_INPUT_INSIDE_REPOSITORY'],
      [['write', ...emu, '--input', path.join(linkToRepo, '..campaign.json')], 'STORE_INPUT_INSIDE_REPOSITORY'],
      [['write', ...emu, '--input', linkToRepoFile], 'STORE_INPUT_INSIDE_REPOSITORY'],
      [['write', ...emu, '--input', synthetic, '--backup', path.join(root, '..backup.json'), '--apply'], 'STORE_BACKUP_INSIDE_REPOSITORY'],
      [['write', ...emu, '--input', synthetic, '--backup', path.join(root, '..private', 'b.json'), '--apply'], 'STORE_BACKUP_INSIDE_REPOSITORY'],
      [['write', ...emu, '--input', synthetic, '--backup', path.join(linkToRepo, 'b.json'), '--apply'], 'STORE_BACKUP_INSIDE_REPOSITORY'],
      [['write', ...emu, '--input', synthetic, '--backup', path.join(linkToDocs, 'b.json'), '--apply'], 'STORE_BACKUP_INSIDE_REPOSITORY'],
    ];
    for (const [args, code] of cases) {
      if (args.includes('--apply')) {
        let started = false;
        await assert.rejects(main(args, loop, { executorSession: {
          started() { started = true; throw new Error('UNEXPECTED_SDK_START'); },
        } }), { code });
        assert.equal(started, false);
        continue;
      }
      const result = cli(args, loop);
      assert.equal(result.stderr.trim(), `STORE_REFUSED ${code}`, `${args.join(' ')}\n${result.stdout}${result.stderr}`);
      assert.equal(result.status, 1);
    }
    for (const name of ['..backup.json', 'b.json']) {
      await assert.rejects(fs.access(path.join(root, name)));
    }
    await assert.rejects(fs.access(path.join(root, 'docs', 'b.json')));
  } finally {
    for (const file of planted) await fs.rm(file, { force: true });
    await fs.rm(path.join(root, '..private'), { recursive: true, force: true });
    await fs.rm(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------- F6

test('F6: a complete private receipt is persisted before any mutation', async () => {
  const fake = fakeFirebase({ doc: envA });
  const receipt = memoryReceipts();
  const backup = memoryBackup();
  let committedWithReceipt = null;
  fake.db.runTransaction = ((original) => async (fn, options) => {
    committedWithReceipt = structuredClone(receipt.latest('/private/receipt.json'));
    return original(fn, options);
  })(fake.db.runTransaction);
  const result = await runStoreAction(apply(fake, {
    receipt, backup, input: envB, approval: `WRITE:${digestB}`, expectCurrent: digestA, backupPath: '/private/backup-a.json',
  }));
  assert.ok(committedWithReceipt, 'receipt existed when the transaction began');
  assert.equal(committedWithReceipt.status, 'READY_TO_COMMIT');
  assert.equal(committedWithReceipt.action, 'write');
  assert.equal(committedWithReceipt.expectCurrent, digestA);
  assert.equal(committedWithReceipt.previousDigest, digestA);
  assert.equal(committedWithReceipt.intendedDigest, digestB);
  assert.deepEqual(committedWithReceipt.backup, { required: true, path: '/private/backup-a.json', digest: digestA, verified: true });
  assert.deepEqual(committedWithReceipt.rollbackIfCommitted, {
    action: 'write', input: '/private/backup-a.json', inputDigest: digestA, expectCurrent: digestB, approval: `WRITE:${digestA}`, backupRequired: true,
  });
  assert.match(committedWithReceipt.uidSha256, /^[0-9a-f]{64}$/);
  assert.doesNotMatch(JSON.stringify(committedWithReceipt), new RegExp(UID));
  assert.equal(result.outcome, 'committed-verified');
  assert.equal(receipt.latest('/private/receipt.json').status, 'COMMITTED_VERIFIED');
  assert.deepEqual(receipt.log.map(([, status]) => status), ['PREPARED', 'READY_TO_COMMIT', 'COMMITTED_VERIFIED']);
});

test('F6: a lost transaction acknowledgement is an unknown outcome, attempted once, never retried or called a conflict', async () => {
  let lose = true;
  const fake = fakeFirebase({ commitFault: () => (lose ? (lose = false, unavailable()) : null) });
  const receipt = memoryReceipts();
  await assert.rejects(runStoreAction(apply(fake, { receipt })), (error) => error.code === 'STORE_OUTCOME_UNKNOWN' && error.outcome === 'unknown');
  assert.deepEqual(fake.callbacks, [0], 'the transaction callback ran exactly once');
  assert.deepEqual(fake.commits, ['create'], 'the write committed once');
  const final = receipt.latest('/private/receipt.json');
  assert.equal(final.status, 'OUTCOME_UNKNOWN');
  assert.equal(final.observedDigest, digestA, 'one read records what is live now');
  assert.deepEqual(final.rollbackIfCommitted, { action: 'retract', expectCurrent: digestA, approval: `RETRACT:${digestA}`, backupRequired: true });
});

test('F6: a failed readback after an acknowledged commit is unknown, with what was observed', async () => {
  const unreadable = fakeFirebase({ readbackFault: () => { throw unavailable(); } });
  const r1 = memoryReceipts();
  await assert.rejects(runStoreAction(apply(unreadable, { receipt: r1 })), { code: 'STORE_OUTCOME_UNKNOWN' });
  assert.equal(r1.latest('/private/receipt.json').status, 'OUTCOME_UNKNOWN');
  assert.equal(r1.latest('/private/receipt.json').observedDigest, 'unreadable');
  assert.deepEqual(unreadable.commits, ['create']);

  // Someone else's write lands between commit and readback.
  const raced = fakeFirebase({ readbackFault: () => ({ exists: true, data: () => structuredClone(envC) }) });
  const r2 = memoryReceipts();
  await assert.rejects(runStoreAction(apply(raced, { receipt: r2 })), { code: 'STORE_OUTCOME_UNKNOWN' });
  assert.equal(r2.latest('/private/receipt.json').observedDigest, digestC);
  assert.deepEqual(raced.callbacks, [0]);
});

test('F6: a concurrent update before commit is a pre-write refusal with nothing written', async () => {
  const fake = fakeFirebase({ doc: envA });
  const original = fake.db.runTransaction;
  fake.db.runTransaction = async (fn, options) => {
    // Another writer replaces the document after the plan read.
    await original(async (tx) => tx.set(null, envC), { maxAttempts: 1 });
    fake.commits.length = 0;
    return original(fn, options);
  };
  const receipt = memoryReceipts();
  await assert.rejects(runStoreAction(apply(fake, {
    receipt, input: envB, approval: `WRITE:${digestB}`, expectCurrent: digestA, backupPath: '/private/b.json',
  })), (error) => error.code === 'STORE_CONCURRENT_CHANGE' && error.outcome === 'refused-before-write');
  assert.deepEqual(fake.commits, []);
  assert.equal(envelopeDigest(fake.current()), digestC);
  assert.equal(receipt.latest('/private/receipt.json').status, 'REFUSED_PRE_WRITE');
  assert.equal(receipt.latest('/private/receipt.json').refusal, 'STORE_CONCURRENT_CHANGE');
});

test('F6: a backup failure or a missing receipt stops before any mutation', async () => {
  const fake = fakeFirebase({ doc: envA });
  const receipt = memoryReceipts();
  await assert.rejects(runStoreAction(apply(fake, {
    receipt, backup: memoryBackup({ fail: true }), input: envB, approval: `WRITE:${digestB}`, expectCurrent: digestA, backupPath: '/private/b.json',
  })), (error) => error.code === 'STORE_BACKUP_FAILED' && error.outcome === 'refused-before-write');
  assert.deepEqual(fake.commits, []);
  assert.deepEqual(fake.callbacks, []);
  assert.equal(receipt.latest('/private/receipt.json').status, 'REFUSED_PRE_WRITE');

  const noReceipt = fakeFirebase();
  await assert.rejects(runStoreAction({ ...apply(noReceipt), receipt: undefined, receiptPath: undefined }), { code: 'STORE_RECEIPT_REQUIRED' });
  const failing = { create: async () => { throw new Error('read-only fs (synthetic)'); }, update: async () => {} };
  await assert.rejects(runStoreAction(apply(noReceipt, { receipt: failing })), { code: 'STORE_RECEIPT_FAILED' });
  assert.deepEqual(noReceipt.commits, []);
});

test('F6: a replacement is undone exactly by the rollback its receipt records', async () => {
  const fake = fakeFirebase();
  await runStoreAction(apply(fake));
  const backup = memoryBackup();
  const receipt = memoryReceipts();
  await runStoreAction(apply(fake, {
    receipt, backup, input: envB, approval: `WRITE:${digestB}`, expectCurrent: digestA, backupPath: '/private/backup-a.json',
  }));
  assert.equal(envelopeDigest(fake.current()), digestB);
  const plan = receipt.latest('/private/receipt.json').rollbackIfCommitted;
  // Run exactly the recorded rollback, reading the recorded backup.
  const restored = backup.files.get(plan.input);
  assert.equal(envelopeDigest(restored), plan.inputDigest);
  const result = await runStoreAction(apply(fake, {
    action: plan.action, input: restored, approval: plan.approval, expectCurrent: plan.expectCurrent,
    backupPath: '/private/backup-b.json', receiptPath: '/private/receipt-rollback.json',
  }));
  assert.equal(result.outcome, 'committed-verified');
  assert.equal(envelopeDigest(fake.current()), digestA);
});

// ---------------------------------------------------------------- Auth claim-change race

test('claim race: a claim revoked after planning stops the write at the last read before commit', async () => {
  const revoked = owner({ customClaims: { other: 'kept' }, tokensValidAfterTime: 'Sun, 15 Nov 2026 01:00:00 GMT' });
  // Eligible when planned; revoked by the time the commit is prepared.
  const fake = fakeFirebase({ users: [owner(), revoked] });
  const receipt = memoryReceipts();
  await assert.rejects(runStoreAction(apply(fake, { receipt })), (error) => error.code === 'STORE_OWNER_CHANGED_BEFORE_COMMIT' && error.outcome === 'refused-before-write');
  assert.deepEqual(fake.commits, []);
  assert.equal(receipt.latest('/private/receipt.json').status, 'REFUSED_PRE_WRITE');
});

test('claim race: any change to the owner record between planning and commit stops the write', async () => {
  for (const changed of [
    owner({ tokensValidAfterTime: 'Sun, 15 Nov 2026 02:00:00 GMT' }),
    owner({ customClaims: { blitzOwner: true, other: 'changed' } }),
    owner({ disabled: true }),
  ]) {
    const fake = fakeFirebase({ users: [owner(), owner(), changed] });
    await assert.rejects(runStoreAction(apply(fake)), { code: 'STORE_OWNER_CHANGED_BEFORE_COMMIT' });
    assert.deepEqual(fake.commits, []);
  }
});

test('claim race: a claim change during the commit is reported, with the exact rollback, not called verified', async () => {
  const revoked = owner({ customClaims: { other: 'kept' }, tokensValidAfterTime: 'Sun, 15 Nov 2026 01:00:00 GMT' });
  const fake = fakeFirebase({ users: [owner(), owner(), owner(), revoked] });
  const receipt = memoryReceipts();
  await assert.rejects(runStoreAction(apply(fake, { receipt })), (error) => error.code === 'STORE_ELIGIBILITY_CHANGED_DURING_COMMIT' && error.outcome === 'committed-eligibility-changed');
  assert.deepEqual(fake.commits, ['create']);
  const final = receipt.latest('/private/receipt.json');
  assert.equal(final.status, 'COMMITTED_ELIGIBILITY_CHANGED');
  assert.deepEqual(final.rollbackIfCommitted, { action: 'retract', expectCurrent: digestA, approval: `RETRACT:${digestA}`, backupRequired: true });
});

test('retract stays possible for a revoked owner and still writes a receipt first', async () => {
  const revoked = owner({ customClaims: {}, disabled: true });
  const fake = fakeFirebase({ doc: envA, users: [revoked] });
  const receipt = memoryReceipts();
  const result = await runStoreAction(apply(fake, {
    receipt, action: 'retract', input: null, approval: `RETRACT:${digestA}`, expectCurrent: digestA, backupPath: '/private/b.json',
  }));
  assert.equal(result.outcome, 'committed-verified');
  assert.equal(fake.current(), null);
  assert.deepEqual(receipt.log.map(([, status]) => status), ['PREPARED', 'READY_TO_COMMIT', 'COMMITTED_VERIFIED']);
  assert.equal(digestB.length, 64);
});
