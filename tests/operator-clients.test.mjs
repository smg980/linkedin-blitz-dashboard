// R3 (and later R4/R5): Step D production mode run through the real entry
// point, main(), with the real pinned firebase-admin / @google-cloud/firestore /
// google-auth-library clients. Only the endpoints are local: synthetic
// credentials, a local TLS gRPC Firestore, a local TLS Identity Toolkit, and an
// in-memory OAuth token transporter. No Google endpoint, real credential or
// campaign data is used.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { envelopeDigest, PRODUCTION_PROJECT, StoreRefusal } from '../secure/campaign-store.mjs';
import { encryptEnvelope } from '../secure/envelope.mjs';
import { syntheticPayload } from '../secure/synthetic-contacts.mjs';
import {
  isolateProcessNetwork, makeLocalTls, opensslAvailable, startFirestoreServer, startIdentityToolkit,
  SYNTHETIC_ACCESS_TOKEN, SYNTHETIC_ADC, syntheticOwnerRecord, tokenTransporter,
} from './helpers/google-transport.mjs';

isolateProcessNetwork();
const HAVE_OPENSSL = opensslAvailable();
const TLS = HAVE_OPENSSL ? await makeLocalTls() : null;
// grpc-js reads its default trust roots lazily, once; set before any channel.
if (TLS) process.env.GRPC_DEFAULT_SSL_ROOTS_FILE_PATH = TLS.certPath;

const { bindOperatorIdentity, main } = await import('../scripts/blitz-campaign-store.mjs');

const UID = 'syntheticOwnerUid01';
const PASS = 'synthetic-operator-clients-passphrase';
const envelope = await encryptEnvelope(syntheticPayload(), PASS);
const digest = envelopeDigest(envelope);

async function tempDir(prefix, root = os.tmpdir()) {
  return fs.realpath(await fs.mkdtemp(path.join(root, prefix)));
}

async function harness({ commitFault, initialFields, onBatchGet, workRoot } = {}) {
  const firestore = await startFirestoreServer({ tls: TLS, commitFault, initialFields, onBatchGet });
  const identity = await startIdentityToolkit({ tls: TLS, user: syntheticOwnerRecord(UID) });
  const tokens = tokenTransporter();
  const work = await tempDir('blitz-r3-', workRoot);
  const lockDir = path.join(work, 'lock');
  const tokenInfoCalls = [];
  const deps = {
    loadOperatorCredential: async () => ({ ...SYNTHETIC_ADC }),
    bindOperatorIdentity: ({ credential }) => bindOperatorIdentity({
      credential,
      fetchImpl: async (url, init) => {
        tokenInfoCalls.push(new URLSearchParams(init.body).get('access_token'));
        return { ok: true, json: async () => ({ email: 'owner-synthetic@example.com', email_verified: 'true' }) };
      },
      gcloud: () => 'owner-synthetic@example.com',
    }),
    testTransport: { tokenTransporter: tokens, servicePath: 'localhost', port: firestore.port, httpAgent: identity.agent },
  };
  const input = path.join(work, 'envelope.json');
  await fs.writeFile(input, JSON.stringify(envelope));
  return {
    firestore, identity, tokens, tokenInfoCalls, deps, work, lockDir, input,
    async close() {
      await firestore.close();
      await identity.close();
      await fs.rm(work, { recursive: true, force: true });
    },
  };
}

const writeArgs = (h, receipt) => ['write', '--target', 'production', '--project', PRODUCTION_PROJECT, '--input', h.input,
  '--expect-current', 'none', '--receipt', receipt, '--apply'];
const writeEnv = (h) => ({
  BLITZ_STORE_UID: UID, BLITZ_STORE_CONFIRM_UID: UID, BLITZ_STORE_APPROVAL: `WRITE:${digest}`, BLITZ_OPERATOR_LOCK_DIR: h.lockDir,
});

test('R3: production inspect initializes Auth and Firestore from the checked user credential', { skip: !HAVE_OPENSSL && 'openssl unavailable' }, async () => {
  const h = await harness();
  try {
    const result = await main(['inspect', '--target', 'production', '--project', PRODUCTION_PROJECT],
      { BLITZ_STORE_UID: UID }, h.deps);
    assert.equal(result.dryRun, true);
    assert.equal(result.ownerEligible, true, 'Auth getUser reached Identity Toolkit and parsed the synthetic owner');
    assert.equal(result.documentExists, false, 'Firestore BatchGetDocuments reached the local server');
    assert.equal(result.operatorIdentityBound, true);
    // One refresh client served every caller: tokeninfo, Auth and Firestore.
    assert.ok(h.tokens.calls.length >= 1);
    assert.ok(h.tokens.calls.every((c) => c.method === 'POST'));
    assert.deepEqual(h.tokenInfoCalls, [SYNTHETIC_ACCESS_TOKEN]);
    assert.ok(h.identity.seen.length >= 1);
    assert.ok(h.identity.seen.every((r) => r.authorization === `Bearer ${SYNTHETIC_ACCESS_TOKEN}`));
    assert.ok(h.firestore.state.authorizations.length >= 1);
    assert.ok(h.firestore.state.authorizations.every((a) => a === `Bearer ${SYNTHETIC_ACCESS_TOKEN}`));
    assert.equal(h.firestore.state.commits.length, 0, 'inspect never commits');
  } finally {
    await h.close();
  }
});

test('R3: production write commits once through the transaction and verifies the readback', { skip: !HAVE_OPENSSL && 'openssl unavailable' }, async () => {
  const h = await harness();
  try {
    const receipt = path.join(h.work, 'receipt.json');
    const result = await main(writeArgs(h, receipt), writeEnv(h), h.deps);
    assert.equal(result.outcome, 'committed-verified');
    assert.equal(result.liveDigest, digest);
    assert.equal(h.firestore.state.commits.length, 1);
    assert.equal(JSON.parse(await fs.readFile(receipt, 'utf8')).status, 'COMMITTED_VERIFIED');
  } finally {
    await h.close();
  }
});

test('R3: a non-user credential is refused before any client exists', async () => {
  const { createOperatorClients } = await import('../secure/operator-clients.mjs');
  for (const adc of [null, { type: 'service_account' }, { type: 'external_account' }]) {
    assert.throws(() => createOperatorClients({ adc, projectId: PRODUCTION_PROJECT }),
      (e) => e instanceof StoreRefusal && e.code === 'STORE_ADC_NOT_USER_CREDENTIAL');
  }
});

// R5: maxAttempts 1 only stops the transaction runner. The GAPIC config for
// Commit retries UNAVAILABLE and RESOURCE_EXHAUSTED with backoff, so a commit
// that applied and lost its acknowledgement was sent again. Count the RPCs.
for (const [label, status, applies] of [
  ['UNAVAILABLE after the write applied (lost acknowledgement)', 'UNAVAILABLE', true],
  ['RESOURCE_EXHAUSTED before the write applied', 'RESOURCE_EXHAUSTED', false],
]) {
  test(`R5: a Commit failing with ${label} is sent exactly once and reported unknown`, { skip: !HAVE_OPENSSL && 'openssl unavailable', timeout: 60000 }, async () => {
    let grpcStatus;
    const h = await harness({
      commitFault: (attempt, request, apply) => {
        if (attempt > 1) { apply(); return null; } // a retry would "succeed"
        if (applies) apply();
        return { code: grpcStatus[status], details: `synthetic ${status}` };
      },
    });
    grpcStatus = h.firestore.grpcStatus;
    try {
      const receipt = path.join(h.work, 'receipt.json');
      const error = await main(writeArgs(h, receipt), writeEnv(h), h.deps).catch((e) => e);
      assert.equal(h.firestore.state.commits.length, 1, 'Commit RPCs sent');
      assert.ok(error instanceof StoreRefusal, 'the run does not report success');
      assert.equal(error.code, 'STORE_OUTCOME_UNKNOWN');
      assert.equal(error.outcome, 'unknown');
      assert.equal(JSON.parse(await fs.readFile(receipt, 'utf8')).status, 'OUTCOME_UNKNOWN');
    } finally {
      await h.close();
    }
  });
}

test('R5: production and emulator Firestore settings disable Commit and channel retries', async () => {
  const { firestoreSettings, COMMIT_NO_RETRY_CLIENT_CONFIG } = await import('../secure/operator-clients.mjs');
  const settings = firestoreSettings({ projectId: PRODUCTION_PROJECT });
  assert.equal(settings.preferRest, false);
  assert.equal(settings['grpc.enable_retries'], 0);
  assert.equal(settings['grpc.service_config_disable_resolution'], 1);
  assert.equal(settings.clientConfig, COMMIT_NO_RETRY_CLIENT_CONFIG);
  const service = COMMIT_NO_RETRY_CLIENT_CONFIG.interfaces['google.firestore.v1.Firestore'];
  assert.deepEqual(service.retry_codes[service.methods.Commit.retry_codes_name], []);
});

// R4: cleanup (lock release, client shutdown) runs in `finally`. A cleanup
// failure must never replace a committed or unknown outcome with a refusal.
const { acquireOperatorLock } = await import('../secure/operator-lock.mjs');
const { completionExitCode, exitCodeFor, failureLine } = await import('../scripts/blitz-campaign-store.mjs');
const failingRelease = (released) => async (options) => {
  const lock = await acquireOperatorLock(options);
  return {
    file: lock.file,
    async release() {
      await lock.release();
      released.push(true);
      throw Object.assign(new Error('EIO: synthetic cleanup failure /private/path'), { code: 'EIO' });
    },
  };
};

test('R4: a cleanup failure after a verified commit keeps the committed outcome', { skip: !HAVE_OPENSSL && 'openssl unavailable' }, async () => {
  const h = await harness();
  try {
    const released = [];
    const receipt = path.join(h.work, 'receipt.json');
    const outcome = await main(writeArgs(h, receipt), writeEnv(h), { ...h.deps, acquireOperatorLock: failingRelease(released) })
      .then((result) => ({ result }), (error) => ({ error }));
    assert.equal(released.length, 1, 'cleanup ran');
    assert.equal(h.firestore.state.commits.length, 1);
    assert.ok(outcome.result, `committed run must not surface as ${outcome.error?.code ?? outcome.error}`);
    assert.equal(outcome.result.outcome, 'committed-verified');
    assert.equal(outcome.result.cleanupComplete, false);
    assert.deepEqual(outcome.result.cleanupFailures, ['LOCK_RELEASE_FAILED']);
    assert.equal(completionExitCode(outcome), 10, 'never the success exit');
  } finally {
    await h.close();
  }
});

test('R4: a cleanup failure after an unresolved commit keeps STORE_OUTCOME_UNKNOWN (exit 3)', { skip: !HAVE_OPENSSL && 'openssl unavailable' }, async () => {
  let grpcStatus;
  const h = await harness({ commitFault: (attempt, request, apply) => { apply(); return { code: grpcStatus.UNAVAILABLE, details: 'synthetic' }; } });
  grpcStatus = h.firestore.grpcStatus;
  try {
    const released = [];
    const receipt = path.join(h.work, 'receipt.json');
    const error = await main(writeArgs(h, receipt), writeEnv(h), { ...h.deps, acquireOperatorLock: failingRelease(released) }).catch((e) => e);
    assert.equal(released.length, 1, 'cleanup ran');
    assert.ok(error instanceof StoreRefusal, `got ${error}`);
    assert.equal(error.code, 'STORE_OUTCOME_UNKNOWN');
    assert.equal(exitCodeFor(error), 3);
    assert.equal(completionExitCode({ error }), 13);
    assert.match(failureLine(error), /^STORE_UNRESOLVED STORE_OUTCOME_UNKNOWN CLEANUP_INCOMPLETE LOCK_RELEASE_FAILED$/);
  } finally {
    await h.close();
  }
});

test('R4: a cleanup failure after a refusal stays a refusal and leaks nothing', { skip: !HAVE_OPENSSL && 'openssl unavailable' }, async () => {
  const h = await harness();
  try {
    const released = [];
    const receipt = path.join(h.work, 'receipt.json');
    const env = { ...writeEnv(h), BLITZ_STORE_APPROVAL: 'WRITE:wrong' };
    const error = await main(writeArgs(h, receipt), env, { ...h.deps, acquireOperatorLock: failingRelease(released) }).catch((e) => e);
    assert.equal(released.length, 1);
    assert.equal(error.code, 'STORE_APPROVAL_REQUIRED');
    assert.equal(exitCodeFor(error), 1);
    assert.equal(completionExitCode({ error }), 11);
    assert.doesNotMatch(failureLine(error), /EIO|private/);
    assert.equal(h.firestore.state.commits.length, 0);
  } finally {
    await h.close();
  }
});

// R4 (Codex f82bb16): the lock is genuinely retained or unverifiable. These use
// the real acquireOperatorLock and inject failures into the real filesystem
// calls release() makes (its in-process `io` seam), so the lock file on disk is
// really left behind. A leftover lock is conservative, but the run must not
// signal complete success, and the mutation outcome must be preserved.
const realFs = fs;
const ioFault = (fault) => ({
  lstat: (...a) => (fault.lstat ? fault.lstat(...a) : realFs.lstat(...a)),
  readFile: (...a) => (fault.readFile ? fault.readFile(...a) : realFs.readFile(...a)),
  unlink: (...a) => (fault.unlink ? fault.unlink(...a) : realFs.unlink(...a)),
});
const eio = (what) => async () => { throw Object.assign(new Error(`EIO: synthetic ${what} /private/path`), { code: 'EIO' }); };
const lockWithIo = (fault, seen) => async (options) => {
  const lock = await acquireOperatorLock({ ...options, io: ioFault(fault) });
  seen.file = lock.file;
  return lock;
};
const lockStillHeld = async (seen) => realFs.lstat(seen.file).then((i) => i.isFile(), () => false);

for (const [label, fault, code] of [
  ['unlink fails (the lock stays held)', { unlink: eio('unlink') }, 'LOCK_RELEASE_UNLINK_FAILED'],
  ['the lock cannot be read (EIO)', { readFile: eio('read') }, 'LOCK_RELEASE_UNREADABLE'],
  ['the lock cannot be stat-ed (EIO)', { lstat: eio('lstat') }, 'LOCK_RELEASE_UNREADABLE'],
]) {
  test(`R4: committed-verified when ${label}: outcome kept, exit 10, lock left, fixed code`, { skip: !HAVE_OPENSSL && 'openssl unavailable' }, async () => {
    const h = await harness();
    try {
      const seen = {};
      const receipt = path.join(h.work, 'receipt.json');
      const result = await main(writeArgs(h, receipt), writeEnv(h), { ...h.deps, acquireOperatorLock: lockWithIo(fault, seen) });
      assert.equal(result.outcome, 'committed-verified');
      assert.equal(result.cleanupComplete, false);
      assert.deepEqual(result.cleanupFailures, [code]);
      assert.equal(completionExitCode({ result }), 10);
      assert.equal(h.firestore.state.commits.length, 1);
      assert.equal(JSON.parse(await fs.readFile(receipt, 'utf8')).status, 'COMMITTED_VERIFIED');
      assert.equal(await lockStillHeld(seen), true, 'the real lock file is still present');
      assert.doesNotMatch(JSON.stringify(result), /EIO|private/);
      // The retained lock fails closed for the next run.
      const again = await main(writeArgs(h, path.join(h.work, 'receipt-2.json')), writeEnv(h), h.deps).catch((e) => e);
      assert.equal(again.code, 'STORE_OPERATOR_LOCK_HELD');
      assert.equal(h.firestore.state.commits.length, 1);
    } finally {
      await h.close();
    }
  });
}

test('R4: an unknown outcome with an unreadable lock stays STORE_OUTCOME_UNKNOWN (exit 13), receipt OUTCOME_UNKNOWN', { skip: !HAVE_OPENSSL && 'openssl unavailable' }, async () => {
  let grpcStatus;
  const h = await harness({ commitFault: (attempt, request, apply) => { apply(); return { code: grpcStatus.UNAVAILABLE, details: 'synthetic' }; } });
  grpcStatus = h.firestore.grpcStatus;
  try {
    const seen = {};
    const receipt = path.join(h.work, 'receipt.json');
    const error = await main(writeArgs(h, receipt), writeEnv(h), { ...h.deps, acquireOperatorLock: lockWithIo({ readFile: eio('read') }, seen) }).catch((e) => e);
    assert.ok(error instanceof StoreRefusal);
    assert.equal(error.code, 'STORE_OUTCOME_UNKNOWN');
    assert.equal(error.outcome, 'unknown');
    assert.deepEqual(error.cleanupFailures, ['LOCK_RELEASE_UNREADABLE']);
    assert.equal(completionExitCode({ error }), 13);
    assert.equal(failureLine(error), 'STORE_UNRESOLVED STORE_OUTCOME_UNKNOWN CLEANUP_INCOMPLETE LOCK_RELEASE_UNREADABLE');
    assert.equal(JSON.parse(await fs.readFile(receipt, 'utf8')).status, 'OUTCOME_UNKNOWN');
    assert.equal(h.firestore.state.commits.length, 1);
    assert.equal(await lockStillHeld(seen), true);
  } finally {
    await h.close();
  }
});

test('R4: a pre-write refusal with a failed unlink stays a refusal (exit 11), nothing written', { skip: !HAVE_OPENSSL && 'openssl unavailable' }, async () => {
  const h = await harness();
  try {
    const seen = {};
    const env = { ...writeEnv(h), BLITZ_STORE_APPROVAL: 'WRITE:wrong' };
    const error = await main(writeArgs(h, path.join(h.work, 'receipt.json')), env, { ...h.deps, acquireOperatorLock: lockWithIo({ unlink: eio('unlink') }, seen) }).catch((e) => e);
    assert.equal(error.code, 'STORE_APPROVAL_REQUIRED');
    assert.equal(completionExitCode({ error }), 11);
    assert.equal(failureLine(error), 'STORE_REFUSED STORE_APPROVAL_REQUIRED CLEANUP_INCOMPLETE LOCK_RELEASE_UNLINK_FAILED');
    assert.equal(h.firestore.state.commits.length, 0);
    assert.equal(await lockStillHeld(seen), true);
  } finally {
    await h.close();
  }
});

for (const [label, tamper, code, held] of [
  ['removed by someone else', async (file) => realFs.unlink(file), 'LOCK_RELEASE_MISSING', false],
  ['replaced by another holder', async (file) => { await realFs.unlink(file); await realFs.writeFile(file, '{"nonce":"someone-else"}\n', { mode: 0o600 }); }, 'LOCK_RELEASE_NOT_OWNED', true],
  ['rewritten in place with another nonce', async (file) => realFs.writeFile(file, '{"nonce":"someone-else"}\n'), 'LOCK_RELEASE_NOT_OWNED', true],
]) {
  test(`R4: a lock ${label} during the run is never reported as released`, { skip: !HAVE_OPENSSL && 'openssl unavailable' }, async () => {
    const h = await harness();
    try {
      const seen = {};
      const deps = { ...h.deps, acquireOperatorLock: async (options) => {
        const lock = await acquireOperatorLock(options);
        seen.file = lock.file;
        return { file: lock.file, release: async () => { await tamper(lock.file); return lock.release(); } };
      } };
      const result = await main(writeArgs(h, path.join(h.work, 'receipt.json')), writeEnv(h), deps);
      assert.equal(result.outcome, 'committed-verified');
      assert.deepEqual(result.cleanupFailures, [code]);
      assert.equal(completionExitCode({ result }), 10);
      assert.equal(await lockStillHeld(seen), held, 'another holder\'s lock is never removed');
    } finally {
      await h.close();
    }
  });
}

test('R4: a clean run exits 0 and leaves no lock', { skip: !HAVE_OPENSSL && 'openssl unavailable' }, async () => {
  const h = await harness();
  try {
    const seen = {};
    const result = await main(writeArgs(h, path.join(h.work, 'receipt.json')), writeEnv(h), { ...h.deps, acquireOperatorLock: lockWithIo({}, seen) });
    assert.equal(result.outcome, 'committed-verified');
    assert.equal(result.cleanupComplete, undefined);
    assert.equal(completionExitCode({ result }), 0);
    assert.equal(await lockStillHeld(seen), false);
  } finally {
    await h.close();
  }
});

test('R4: the CLI exits only through completionExitCode, never an unconditional 0', async () => {
  const source = await fs.readFile(new URL('../scripts/blitz-campaign-store.mjs', import.meta.url), 'utf8');
  const cli = source.slice(source.lastIndexOf('if (process.argv[1]'));
  assert.doesNotMatch(cli, /process\.exit\(\s*0\s*\)/);
  assert.equal([...cli.matchAll(/process\.exit\(completionExitCode\(\{ (result|error) \}\)\)/g)].length, 2);
  assert.match(cli, /cleanupIncompleteLine\(result\)/);
});

test('R4: completion exit codes are distinct for every outcome with and without cleanup', () => {
  const err = (outcome, cleanupComplete) => Object.assign(new StoreRefusal('X'), outcome ? { outcome } : {}, cleanupComplete === false ? { cleanupComplete } : {});
  const codes = [
    completionExitCode({ result: {} }), completionExitCode({ result: { cleanupComplete: false } }),
    ...[undefined, 'unknown', 'committed-eligibility-changed', 'committed-verified'].flatMap((o) => [completionExitCode({ error: err(o) }), completionExitCode({ error: err(o, false) })]),
  ];
  assert.deepEqual(codes, [0, 10, 1, 11, 3, 13, 4, 14, 5, 15]);
  assert.equal(new Set(codes).size, codes.length);
  assert.equal(completionExitCode({ error: new Error('x') }), 1);
});

test('R4: runCleanup attempts every step, bounds a hanging one and reports incompleteness', async () => {
  const { runCleanup } = await import('../scripts/blitz-campaign-store.mjs');
  const ran = [];
  const started = Date.now();
  const complete = await runCleanup([
    () => { ran.push('throws'); throw new Error('synthetic'); },
    () => { ran.push('hangs'); return new Promise(() => {}); },
    null,
    async () => { ran.push('last'); },
  ]);
  assert.equal(complete, false);
  assert.deepEqual(ran, ['throws', 'hangs', 'last']);
  assert.ok(Date.now() - started < 10000);
  assert.equal(await runCleanup([async () => {}, null]), true);
});

// R6: the backup and receipt directories are checked (real path, outside the
// repository) when the run starts, but the files are created later, after
// network round trips. If the checked directory is replaced by a symlink into
// the repository in between, path-based creation follows it. The swap happens
// at the first or second Firestore read, as a racing process would.
const { encodeFields } = await import('./helpers/google-transport.mjs');
const { fileURLToPath } = await import('node:url');
const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const envB = await encryptEnvelope({ ...syntheticPayload(), generatedAt: 'r6-second' }, PASS);
const digestB = envelopeDigest(envB);

async function swapTarget() {
  return fs.mkdtemp(path.join(REPO, '.r6-swap-target-'));
}

async function filesUnder(dir) {
  const out = [];
  for (const name of await fs.readdir(dir).catch(() => [])) {
    const full = path.join(dir, name);
    const info = await fs.lstat(full);
    out.push({ name, size: info.size, text: info.isFile() ? await fs.readFile(full, 'utf8') : '' });
  }
  return out;
}

function swapAt(n, dir, target) {
  return async (count) => {
    if (count !== n) return;
    await fs.rename(dir, `${dir}.moved`);
    await fs.symlink(target, dir, 'dir');
  };
}

async function replaceRun({ swap }) {
  const target = await swapTarget();
  const holder = {};
  const h = await harness({ initialFields: encodeFields(envelope), onBatchGet: (n) => holder.hook?.(n) });
  const backupDir = path.join(h.work, 'backup-dir');
  const receiptDir = path.join(h.work, 'receipt-dir');
  await fs.mkdir(backupDir, { mode: 0o700 });
  await fs.mkdir(receiptDir, { mode: 0o700 });
  const input = path.join(h.work, 'envelope-b.json');
  await fs.writeFile(input, JSON.stringify(envB));
  holder.hook = swap({ backupDir, receiptDir, target });
  const args = ['write', '--target', 'production', '--project', PRODUCTION_PROJECT, '--input', input,
    '--expect-current', digest, '--backup', path.join(backupDir, 'backup.json'), '--receipt', path.join(receiptDir, 'receipt.json'), '--apply'];
  const env = { ...writeEnv(h), BLITZ_STORE_APPROVAL: `WRITE:${digestB}` };
  const outcome = await main(args, env, h.deps).then((result) => ({ result }), (error) => ({ error }));
  const leaked = await filesUnder(target);
  return { h, outcome, leaked, target };
}

const R6 = { skip: !HAVE_OPENSSL && 'openssl unavailable' };

test('R6: a backup directory swapped for a symlink into the repository receives no ciphertext and nothing commits', R6, async () => {
  const { h, outcome, leaked, target } = await replaceRun({ swap: ({ backupDir, target: t }) => swapAt(1, backupDir, t) });
  try {
    assert.deepEqual(leaked.filter((f) => f.size > 0).map((f) => f.name), [], 'no content written inside the repository');
    assert.ok(!leaked.some((f) => f.text.includes(envelope.ct)), 'no ciphertext inside the repository');
    assert.equal(h.firestore.state.commits.length, 0);
    assert.equal(outcome.error?.code, 'STORE_BACKUP_FAILED');
    assert.equal(outcome.error?.outcome, 'refused-before-write');
  } finally {
    await fs.rm(target, { recursive: true, force: true });
    await h.close();
  }
});

test('R6: a receipt directory swapped before the receipt exists receives nothing and nothing commits', R6, async () => {
  const { h, outcome, leaked, target } = await replaceRun({ swap: ({ receiptDir, target: t }) => swapAt(1, receiptDir, t) });
  try {
    assert.deepEqual(leaked.filter((f) => f.size > 0).map((f) => f.name), []);
    assert.equal(h.firestore.state.commits.length, 0);
    assert.equal(outcome.error?.code, 'STORE_RECEIPT_FAILED');
    assert.equal(outcome.error?.outcome, 'refused-before-write');
  } finally {
    await fs.rm(target, { recursive: true, force: true });
    await h.close();
  }
});

test('R6: a receipt directory swapped mid-run never receives a receipt update; the commit is still reported', R6, async () => {
  const { h, outcome, leaked, target } = await replaceRun({ swap: ({ receiptDir, target: t }) => swapAt(2, receiptDir, t) });
  try {
    assert.deepEqual(leaked.filter((f) => f.size > 0).map((f) => f.name), [], 'no receipt content inside the repository');
    // The commit happened and was verified; only the receipt could not record it (exit 5).
    assert.equal(h.firestore.state.commits.length, 1);
    assert.equal(outcome.error?.code, 'STORE_RECEIPT_FAILED_AFTER_COMMIT');
    assert.equal(outcome.error?.outcome, 'committed-verified');
  } finally {
    await fs.rm(target, { recursive: true, force: true });
    await h.close();
  }
});

test('R6: backup and receipt directories must be private to the operator', R6, async () => {
  const h = await harness({ initialFields: encodeFields(envelope) });
  try {
    const open = path.join(h.work, 'open-dir');
    await fs.mkdir(open);
    await fs.chmod(open, 0o755);
    const input = path.join(h.work, 'envelope-b.json');
    await fs.writeFile(input, JSON.stringify(envB));
    const base = ['write', '--target', 'production', '--project', PRODUCTION_PROJECT, '--input', input, '--expect-current', digest, '--apply'];
    const env = { ...writeEnv(h), BLITZ_STORE_APPROVAL: `WRITE:${digestB}` };
    const priv = path.join(h.work, 'priv');
    await fs.mkdir(priv, { mode: 0o700 });
    const e1 = await main([...base, '--backup', path.join(open, 'b.json'), '--receipt', path.join(priv, 'r.json')], env, h.deps).catch((e) => e);
    assert.equal(e1.code, 'STORE_BACKUP_DIRECTORY_NOT_PRIVATE');
    const e2 = await main([...base, '--backup', path.join(priv, 'b.json'), '--receipt', path.join(open, 'r.json')], env, h.deps).catch((e) => e);
    assert.equal(e2.code, 'STORE_RECEIPT_DIRECTORY_NOT_PRIVATE');
    assert.equal(h.firestore.state.commits.length, 0);
  } finally {
    await h.close();
  }
});

// R6 (Codex f82bb16): the descriptor proof raced the path-based open. A parent
// swapped into the repository just before open, then restored, with a hard link
// planted after the first fstat, let 3,580 bytes of fictional ciphertext be
// written into the repository. Every file operation is now anchored to the
// directory held open since the run started (secure/anchored-dir.mjs). These
// hooks run real renames, symlinks and links at the actual await boundaries of
// the anchored create/write/rename; no stat result or writer is replaced.
// The private directory sits beside the repository (same filesystem) so hard
// links and renames into the repository are really possible.
const PARENT = path.dirname(REPO);
const R6B = { skip: !HAVE_OPENSSL && 'openssl unavailable', timeout: 60000 };

async function boundaryRun({ hooks, initial = true, input: inputEnvelope = envB }) {
  const target = await swapTarget();
  const h = await harness({ initialFields: initial ? encodeFields(envelope) : undefined, workRoot: PARENT });
  assert.equal((await fs.stat(h.work)).dev, (await fs.stat(target)).dev, 'precondition: private dir and repository share a filesystem');
  const backupDir = path.join(h.work, 'backup-dir');
  const receiptDir = path.join(h.work, 'receipt-dir');
  await fs.mkdir(backupDir, { mode: 0o700 });
  await fs.mkdir(receiptDir, { mode: 0o700 });
  const input = path.join(h.work, 'envelope-b.json');
  await fs.writeFile(input, JSON.stringify(inputEnvelope));
  const ctx = { h, target, backupDir, receiptDir, backupFile: path.join(backupDir, 'backup.json'), receiptFile: path.join(receiptDir, 'receipt.json') };
  const args = ['write', '--target', 'production', '--project', PRODUCTION_PROJECT, '--input', input,
    '--expect-current', initial ? digest : 'none', '--receipt', ctx.receiptFile, '--apply',
    ...(initial ? ['--backup', ctx.backupFile] : [])];
  const env = { ...writeEnv(h), BLITZ_STORE_APPROVAL: `WRITE:${envelopeDigest(inputEnvelope)}` };
  const outcome = await main(args, env, { ...h.deps, privateFileHooks: hooks(ctx) }).then((result) => ({ result }), (error) => ({ error }));
  ctx.outcome = outcome;
  ctx.leaked = await filesUnder(target);
  return ctx;
}

async function finish(ctx) {
  await fs.rm(ctx.target, { recursive: true, force: true });
  await ctx.h.close();
}

function assertNothingInRepository(ctx) {
  assert.deepEqual(ctx.leaked.filter((f) => f.size > 0).map((f) => `${f.name}:${f.size}`), [], 'no content inside the repository');
  assert.ok(!ctx.leaked.some((f) => f.text.includes(envelope.ct) || f.text.includes('uidSha256')), 'no ciphertext or receipt inside the repository');
}

// Runs `fn` once, at the first call of a boundary for the named file.
const once = (file, fn) => {
  let done = false;
  return async (detail) => {
    if (done || detail?.name !== file) return;
    done = true;
    await fn(detail);
  };
};

test('R6: Codex sequence — parent swapped into the repository before the open, restored, hard link after the first fstat: no repository content, no commit', R6B, async () => {
  const ctx = await boundaryRun({ hooks: (c) => {
    const repoFile = path.join(c.target, 'backup.json');
    return {
      afterAnchor: async () => {
        if (c.swapped || !(await fs.lstat(c.backupDir).then(() => true, () => false))) return;
        if (c.h.firestore.state.commits.length) return;
        // Only on the backup's anchored section: the receipt was created first.
        if (!(await fs.lstat(c.receiptFile).then(() => true, () => false))) return;
        c.swapped = true;
        await fs.rename(c.backupDir, `${c.backupDir}.moved`);
        await fs.symlink(c.target, c.backupDir, 'dir');
      },
      afterFirstFstat: once('backup.json', async ({ opened }) => {
        assert.equal(opened.nlink, 1);
        await fs.unlink(c.backupDir);
        await fs.rename(`${c.backupDir}.moved`, c.backupDir);
        // The anchored create landed in the private directory; link it into the repository.
        await fs.link(c.backupFile, repoFile);
      }),
    };
  } });
  try {
    assert.equal(ctx.swapped, true, 'the swap happened');
    assertNothingInRepository(ctx);
    assert.deepEqual(ctx.leaked.map((f) => f.name), ['backup.json'], 'only the empty linked artifact');
    assert.equal(ctx.h.firestore.state.commits.length, 0);
    assert.equal(ctx.outcome.error?.code, 'STORE_BACKUP_FAILED');
    assert.equal(ctx.outcome.error?.outcome, 'refused-before-write');
    assert.equal((await fs.stat(ctx.backupFile)).size, 0, 'nothing was written');
  } finally {
    await finish(ctx);
  }
});

test('R6: a hard link into the repository planted after the pre-write check is emptied after the write; no commit', R6B, async () => {
  const ctx = await boundaryRun({ hooks: (c) => ({
    beforeWrite: once('backup.json', async () => { await fs.link(c.backupFile, path.join(c.target, 'backup.json')); }),
  }) });
  try {
    assert.deepEqual(ctx.leaked.map((f) => `${f.name}:${f.size}`), ['backup.json:0'], 'the planted link holds zero bytes');
    assertNothingInRepository(ctx);
    assert.equal(ctx.h.firestore.state.commits.length, 0);
    assert.equal(ctx.outcome.error?.code, 'STORE_BACKUP_FAILED');
  } finally {
    await finish(ctx);
  }
});

test('R6: the anchored directory moved into the repository during the write is emptied and refused; no commit', R6B, async () => {
  const ctx = await boundaryRun({ hooks: (c) => ({
    beforeWrite: once('backup.json', async () => { await fs.rename(c.backupDir, path.join(c.target, 'moved-private-dir')); }),
  }) });
  try {
    const moved = await filesUnder(path.join(ctx.target, 'moved-private-dir'));
    assert.deepEqual(moved.map((f) => `${f.name}:${f.size}`), ['backup.json:0']);
    assert.equal(ctx.h.firestore.state.commits.length, 0);
    assert.equal(ctx.outcome.error?.code, 'STORE_BACKUP_FAILED');
  } finally {
    await finish(ctx);
  }
});

test('R6: the directory path swapped into the repository after anchoring cannot redirect create, write or rename', R6B, async () => {
  const ctx = await boundaryRun({ hooks: (c) => ({
    afterCreate: once('receipt.json', async () => {
      await fs.rename(c.receiptDir, `${c.receiptDir}.moved`);
      await fs.symlink(c.target, c.receiptDir, 'dir');
    }),
  }) });
  try {
    assertNothingInRepository(ctx);
    assert.deepEqual(ctx.leaked, []);
    // The receipt was created in the held directory object, now named .moved;
    // later sections re-enter by path, find another directory and refuse.
    assert.ok((await fs.stat(path.join(`${ctx.receiptDir}.moved`, 'receipt.json'))).size > 0);
    assert.equal(ctx.h.firestore.state.commits.length, 0);
    assert.equal(ctx.outcome.error?.outcome, 'refused-before-write');
  } finally {
    await finish(ctx);
  }
});

test('R6: receipt replacement — a link planted on the temp file before the rename is emptied; the commit is still reported (exit 5)', R6B, async () => {
  const ctx = await boundaryRun({ hooks: (c) => {
    return {
      beforeRename: async ({ tempName }) => {
        if (!c.h.firestore.state.commits.length || c.linked) return;
        c.linked = true;
        await fs.link(path.join(c.receiptDir, tempName), path.join(c.target, 'receipt.json'));
      },
    };
  } });
  try {
    assert.equal(ctx.linked, true);
    assertNothingInRepository(ctx);
    assert.equal(ctx.h.firestore.state.commits.length, 1);
    assert.equal(ctx.outcome.error?.code, 'STORE_RECEIPT_FAILED_AFTER_COMMIT');
    assert.equal(ctx.outcome.error?.outcome, 'committed-verified');
  } finally {
    await finish(ctx);
  }
});

test('R6: receipt replacement — a path swap at the rename boundary keeps the rename inside the held directory', R6B, async () => {
  const ctx = await boundaryRun({ hooks: (c) => ({
    beforeRename: async () => {
      if (!c.h.firestore.state.commits.length || c.swapped) return;
      c.swapped = true;
      await fs.rename(c.receiptDir, `${c.receiptDir}.moved`);
      await fs.symlink(c.target, c.receiptDir, 'dir');
    },
  }) });
  try {
    assert.equal(ctx.swapped, true);
    assert.deepEqual(ctx.leaked, [], 'the rename never reached the repository');
    assert.equal(JSON.parse(await fs.readFile(path.join(`${ctx.receiptDir}.moved`, 'receipt.json'), 'utf8')).status, 'COMMITTED_VERIFIED');
    assert.equal(ctx.h.firestore.state.commits.length, 1);
    assert.equal(ctx.outcome.result?.outcome, 'committed-verified');
  } finally {
    await finish(ctx);
  }
});

test('R6: an entry planted at the anchored name is never followed or overwritten', R6B, async () => {
  const victim = path.join(REPO, '.r6-victim-');
  const ctx = await boundaryRun({ hooks: (c) => ({
    afterAnchor: async () => {
      if (c.planted || !(await fs.lstat(c.receiptFile).then(() => true, () => false)) || c.h.firestore.state.commits.length) return;
      c.planted = true;
      c.victim = await fs.mkdtemp(victim);
      await fs.writeFile(path.join(c.victim, 'tracked.txt'), 'original\n');
      await fs.symlink(path.join(c.victim, 'tracked.txt'), c.backupFile);
    },
  }) });
  try {
    assert.equal(ctx.planted, true);
    assert.equal(await fs.readFile(path.join(ctx.victim, 'tracked.txt'), 'utf8'), 'original\n');
    assert.equal(ctx.h.firestore.state.commits.length, 0);
    assert.equal(ctx.outcome.error?.code, 'STORE_BACKUP_FAILED');
  } finally {
    await fs.rm(ctx.victim, { recursive: true, force: true });
    await finish(ctx);
  }
});

test('R6: a clean run through the anchored writers leaves the exact backup and receipt and restores the working directory', R6B, async () => {
  const cwd = process.cwd();
  const ctx = await boundaryRun({ hooks: () => ({}) });
  try {
    assert.equal(process.cwd(), cwd);
    assert.equal(ctx.outcome.result?.outcome, 'committed-verified');
    assert.equal(ctx.outcome.result?.backupWritten, true);
    assert.equal(envelopeDigest(JSON.parse(await fs.readFile(ctx.backupFile, 'utf8'))), digest);
    assert.equal((await fs.stat(ctx.backupFile)).mode & 0o777, 0o600);
    assert.equal(JSON.parse(await fs.readFile(ctx.receiptFile, 'utf8')).status, 'COMMITTED_VERIFIED');
    assert.deepEqual((await fs.readdir(ctx.receiptDir)).sort(), ['receipt.json'], 'no temp file left');
    assert.deepEqual(ctx.leaked, []);
  } finally {
    await finish(ctx);
  }
});
