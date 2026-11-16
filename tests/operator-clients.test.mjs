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

async function tempDir(prefix) {
  return fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), prefix)));
}

async function harness({ commitFault, initialFields, onBatchGet } = {}) {
  const firestore = await startFirestoreServer({ tls: TLS, commitFault, initialFields, onBatchGet });
  const identity = await startIdentityToolkit({ tls: TLS, user: syntheticOwnerRecord(UID) });
  const tokens = tokenTransporter();
  const work = await tempDir('blitz-r3-');
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
const { exitCodeFor, failureLine } = await import('../scripts/blitz-campaign-store.mjs');
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
    assert.match(failureLine(error), /^STORE_UNRESOLVED STORE_OUTCOME_UNKNOWN CLEANUP_INCOMPLETE$/);
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
    assert.doesNotMatch(failureLine(error), /EIO|private/);
    assert.equal(h.firestore.state.commits.length, 0);
  } finally {
    await h.close();
  }
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
