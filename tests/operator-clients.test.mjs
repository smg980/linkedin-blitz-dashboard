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

async function harness({ commitFault } = {}) {
  const firestore = await startFirestoreServer({ tls: TLS, commitFault });
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
