import assert from 'node:assert/strict';
import http from 'node:http';
import { once } from 'node:events';
import test from 'node:test';
import { SettledExecutor } from '../secure/settled-executor.mjs';
import { StoreRefusal } from '../secure/campaign-store.mjs';

const deferred = () => {
  let resolve;
  const promise = new Promise((r) => { resolve = r; });
  return { promise, resolve };
};

function fixture({ terminate, deletion, authFailure } = {}) {
  const events = [];
  let active = false;
  const admission = {
    async acquire() { assert.equal(active, false); active = true; events.push('ACTIVE'); },
    async clean() { events.push('CLEAN'); active = false; },
    async release() { events.push('release'); },
  };
  const rawSnapshot = { exists: true, data: () => ({ value: 'synthetic' }), ref: { firestore: 'raw-client' } };
  const raw = {
    doc: () => ({ async get() { return rawSnapshot; } }),
    async runTransaction(fn) {
      await fn({ async get() { return rawSnapshot; }, create() {}, set() {}, delete() {} });
    },
    async terminate() { events.push('terminate'); await terminate?.(); },
  };
  const openClients = async () => ({
    firestore: raw,
    auth: { async getUser() { if (authFailure) throw authFailure; return { uid: 'synthetic' }; } },
    async deleteApp() { events.push('delete'); await deletion?.(); },
  });
  return { events, admission, raw, executor: () => new SettledExecutor({ admission, openClients }),
    active: () => active };
}

test('executor seals, confirms shutdown, then cleans; repeated settled operations are possible', async () => {
  const h = fixture();
  for (let i = 0; i < 2; i++) {
    const result = await h.executor().run(async () => ({ outcome: 'committed-verified' }));
    assert.equal(result.quarantine, 'CLEAN');
  }
  assert.deepEqual(h.events, ['ACTIVE', 'terminate', 'delete', 'CLEAN', 'release',
    'ACTIVE', 'terminate', 'delete', 'CLEAN', 'release']);
});

test('delayed synthetic Commit stays ACTIVE until the terminal response and SDK teardown', async () => {
  const received = deferred();
  const permit = deferred();
  let commits = 0;
  const server = http.createServer(async (_req, response) => {
    received.resolve();
    await permit.promise;
    commits++;
    response.end('{"committed":true}');
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const h = fixture();
  h.raw.runTransaction = async (fn) => {
    await fn({ create() {} });
    const response = await fetch(`http://127.0.0.1:${server.address().port}/Commit`, { method: 'POST' });
    await response.json();
  };
  try {
    const running = h.executor().run(async ({ db }) => {
      const ref = db.doc('synthetic');
      await db.runTransaction(async (tx) => { tx.create(ref, {}); });
      return { outcome: 'committed-verified' };
    });
    await received.promise;
    assert.equal(h.active(), true);
    assert.deepEqual(h.events, ['ACTIVE']);
    permit.resolve();
    assert.equal((await running).quarantine, 'CLEAN');
    assert.equal(commits, 1);
  } finally {
    permit.resolve();
    await new Promise((resolve) => server.close(resolve));
  }
});

test('unknown outcome is preserved with ACTIVE even when teardown succeeds', async () => {
  const h = fixture();
  const error = Object.assign(new Error('synthetic'), { outcome: 'unknown' });
  const completion = await h.executor().run(async () => { throw error; });
  assert.equal(completion.error, error);
  assert.equal(h.active(), true);
  assert.equal(completion.cleanupComplete, false);
  assert.ok(!h.events.includes('CLEAN'));
});

test('a typed pre-write refusal can settle only when no mutator was invoked', async () => {
  const h = fixture();
  const error = new StoreRefusal('STORE_APPROVAL_REQUIRED');
  const completion = await h.executor().run(async () => { throw error; });
  assert.equal(completion.error, error);
  assert.equal(error.outcome, 'refused-before-write');
  assert.equal(completion.quarantine, 'CLEAN');
  assert.deepEqual(h.events, ['ACTIVE', 'terminate', 'delete', 'CLEAN', 'release']);
});

for (const code of ['auth/user-not-found', 'auth/internal-error']) {
  test(`read refusal ${code} ${code.endsWith('user-not-found') ? 'is terminal' : 'does not prove settlement'}`, async () => {
    const h = fixture({ authFailure: Object.assign(new Error('synthetic'), { code }) });
    const completion = await h.executor().run(async ({ auth }) => {
      try { await auth.getUser('synthetic'); }
      catch { throw new StoreRefusal('STORE_UNKNOWN_UID'); }
    });
    assert.equal(completion.quarantine, code.endsWith('user-not-found') ? 'CLEAN' : 'ACTIVE_OR_UNCONFIRMED');
  });
}

for (const step of ['terminate', 'deletion']) {
  test(`failed ${step} retains ACTIVE and the transaction result`, async () => {
    const h = fixture({ [step]: async () => { throw new Error('synthetic'); } });
    const result = { outcome: 'committed-verified', verified: true };
    const completion = await h.executor().run(async () => result);
    assert.equal(completion.result, result);
    assert.equal(h.active(), true);
    assert.equal(completion.cleanupComplete, false);
    assert.deepEqual(h.events, ['ACTIVE', 'terminate', 'delete', 'release']);
  });
}

test('snapshot and sealed facades cannot expose or reuse raw clients', async () => {
  const h = fixture();
  let retained;
  await h.executor().run(async ({ db }) => {
    retained = db;
    const snapshot = await db.doc('synthetic').get();
    assert.deepEqual(Object.keys(snapshot).sort(), ['data', 'exists']);
    assert.equal(snapshot.ref, undefined);
    const data = snapshot.data();
    data.value = 'changed';
    assert.equal(snapshot.data().value, 'synthetic');
    return { outcome: 'committed-verified' };
  });
  assert.throws(() => retained.doc('synthetic'), /EXECUTOR_SEALED/);
  await assert.rejects(retained.runTransaction(async () => {}), /EXECUTOR_SEALED/);
});

test('unawaited operations forbid CLEAN even if they later finish', async () => {
  const h = fixture();
  const finish = deferred();
  h.raw.doc = () => ({ async get() { await finish.promise; return { exists: false }; } });
  let pending;
  const completion = await h.executor().run(async ({ db }) => {
    pending = db.doc('synthetic').get();
    return { outcome: 'committed-verified' };
  });
  assert.ok(completion.cleanupFailures.includes('EXECUTOR_OUTSTANDING_REQUESTS'));
  finish.resolve();
  await pending;
  assert.equal(h.active(), true);
  assert.ok(!h.events.includes('CLEAN'));
});

test('a hanging shutdown never issues CLEAN; late success requires actual completion', async () => {
  const finish = deferred();
  const started = deferred();
  const h = fixture({ terminate: async () => { started.resolve(); await finish.promise; } });
  const running = h.executor().run(async () => ({ outcome: 'committed-verified' }));
  await started.promise;
  assert.deepEqual(h.events, ['ACTIVE', 'terminate']);
  assert.equal(h.active(), true);
  finish.resolve();
  assert.equal((await running).quarantine, 'CLEAN');
});
