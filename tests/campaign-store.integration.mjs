// Step D campaign store against local Auth and Firestore emulators only
// (project demo-blitz-store). Run through scripts/run-campaign-store-suite.mjs,
// which loads the same emulator rules as the secure-shell suite.
// The Admin SDK writes; the browser client's own read path reads and decrypts.
// This functional suite uses a private in-process executor capability. Real
// CLI/OS admission is covered by trusted-executor-supervisor.test.py.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { after, before, describe, test } from 'node:test';
import { envelopeDigest, isCredentialEnvKey } from '../secure/campaign-store.mjs';
import { decryptEnvelope, encryptEnvelope } from '../secure/envelope.mjs';
import { readPrivateDocument } from '../secure/firestore-get.mjs';
import { syntheticPayload } from '../secure/synthetic-contacts.mjs';
import { runSyntheticOwnerAction } from './helpers/owned-emulator-actions.mjs';
import { main, completionExitCode, failureLine } from '../scripts/blitz-campaign-store.mjs';

const PROJECT = 'demo-blitz-store';
const PASS = 'synthetic-store-integration-passphrase';
const firestoreHost = process.env.FIRESTORE_EMULATOR_HOST;
const authHost = process.env.FIREBASE_AUTH_EMULATOR_HOST;
assert.match(firestoreHost || '', /^(127\.0\.0\.1|localhost):\d+$/, 'Firestore emulator must be loopback');
assert.match(authHost || '', /^(127\.0\.0\.1|localhost):\d+$/, 'Auth emulator must be loopback');

const overall = setTimeout(() => {
  console.error('STOP: campaign store integration exceeded the overall timeout');
  process.exit(1);
}, 5 * 60 * 1000);
overall.unref();

const users = {};
const outputs = [];
let dir;
let files;
let digests;

async function signInGoogle(email, sub) {
  const claims = { sub, email, email_verified: true, name: 'Synthetic' };
  const response = await fetch(`http://${authHost}/identitytoolkit.googleapis.com/v1/accounts:signInWithIdp?key=fake-api-key`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      postBody: `id_token=${encodeURIComponent(JSON.stringify(claims))}&providerId=google.com`,
      requestUri: `http://${authHost}`,
      returnIdpCredential: true,
      returnSecureToken: true,
    }),
  });
  const body = await response.json();
  assert.equal(response.status, 200);
  return { uid: body.localId, idToken: body.idToken, email };
}

let receipts = 0;
async function store(args, { uid, confirmUid, approval } = {}) {
  const env = { ...process.env };
  const lockDir = env.BLITZ_OPERATOR_LOCK_DIR;
  for (const key of Object.keys(env)) {
    if (/^BLITZ_|PASSPHRASE|^CI$|^GITHUB_ACTIONS$/.test(key) || isCredentialEnvKey(key)) delete env[key];
  }
  Object.assign(env, { FIRESTORE_EMULATOR_HOST: firestoreHost, FIREBASE_AUTH_EMULATOR_HOST: authHost, BLITZ_OPERATOR_LOCK_DIR: lockDir });
  // Every apply needs its own private receipt (F6).
  if (args.includes('--apply')) {
    receipts += 1;
    args = [...args, '--receipt', path.join(dir, `receipt-${receipts}.json`)];
  }
  if (uid) env.BLITZ_STORE_UID = uid;
  if (confirmUid) env.BLITZ_STORE_CONFIRM_UID = confirmUid;
  if (approval) env.BLITZ_STORE_APPROVAL = approval;
  let settled = 0;
  try {
    const result = await main([args[0], '--target', 'emulator', '--project', PROJECT, ...args.slice(1)], env,
      { executorSession: { started() {}, settled() { settled++; } } });
    assert.equal(settled, 1, 'successful functional execution confirmed SDK shutdown');
    outputs.push(JSON.stringify(result));
    return { status: completionExitCode({ result }), json: result, refusal: '' };
  } catch (error) {
    const refusal = failureLine(error);
    outputs.push(refusal);
    return { status: completionExitCode({ error }), json: null, refusal };
  }
}

async function clientRead(user) {
  // Fresh sign-in so the ID token carries the current custom claims.
  const session = await signInGoogle(user.email, user.sub);
  return readPrivateDocument({ origin: `http://${firestoreHost}`, projectId: PROJECT, uid: user.uid, token: session.idToken });
}

describe('Step D campaign store on emulators', { concurrency: false }, () => {
  before(async () => {
    dir = await fs.mkdtemp(path.join(os.tmpdir(), 'blitz-store-int-'));
    const owner = await signInGoogle('owner-store@example.com', 'store-owner-sub-1');
    const other = await signInGoogle('other-store@example.com', 'store-other-sub-1');
    users.owner = { ...owner, sub: 'store-owner-sub-1' };
    users.other = { ...other, sub: 'store-other-sub-1' };
    await runSyntheticOwnerAction({ projectId: PROJECT, uid: users.owner.uid, action: 'grant', apply: true,
      confirmUid: users.owner.uid, approval: 'APPLY_SYNTHETIC_ONLY' });
    const a = await encryptEnvelope(syntheticPayload(), PASS);
    const b = await encryptEnvelope({ ...syntheticPayload(), generatedAt: 'synthetic-second-build' }, PASS);
    files = { a: path.join(dir, 'a.json'), b: path.join(dir, 'b.json'), backup1: path.join(dir, 'backup1.json'), backup2: path.join(dir, 'backup2.json') };
    await fs.writeFile(files.a, JSON.stringify(a));
    await fs.writeFile(files.b, JSON.stringify(b));
    digests = { a: envelopeDigest(a), b: envelopeDigest(b) };
  });

  after(async () => {
    await fs.rm(dir, { recursive: true, force: true });
  });

  test('an approved write is readable and decryptable only through the owner client path', async () => {
    const id = { uid: users.owner.uid };
    const inspect = await store(['inspect'], id);
    assert.equal(inspect.status, 0, inspect.refusal);
    assert.deepEqual(inspect.json, { target: 'emulator', dryRun: true, action: 'inspect', ownerEligible: true, documentExists: false, currentDigest: null, requiredExpectCurrent: 'none' });

    const dry = await store(['write', '--input', files.a], id);
    assert.equal(dry.json.dryRun, true);
    assert.equal(dry.json.requiredApproval, `WRITE:${digests.a}`);
    assert.equal((await store(['inspect'], id)).json.documentExists, false);

    const full = { ...id, confirmUid: users.owner.uid, approval: `WRITE:${digests.a}` };
    assert.equal((await store(['write', '--input', files.a, '--expect-current', 'none', '--apply'], { ...id, confirmUid: users.owner.uid })).refusal, 'STORE_REFUSED STORE_APPROVAL_REQUIRED');
    assert.equal((await store(['write', '--input', files.a, '--expect-current', 'none', '--apply'], { ...full, confirmUid: users.other.uid })).refusal, 'STORE_REFUSED STORE_EXACT_UID_CONFIRMATION_REQUIRED');
    assert.equal((await store(['write', '--input', files.a, '--expect-current', 'none', '--apply'], { ...full, approval: `WRITE:${digests.b}` })).refusal, 'STORE_REFUSED STORE_APPROVAL_REQUIRED');
    assert.equal((await clientRead(users.owner)).status, 'missing');

    const written = await store(['write', '--input', files.a, '--expect-current', 'none', '--apply'], full);
    assert.equal(written.status, 0, written.refusal);
    assert.equal(written.json.verified, true);
    assert.equal(written.json.liveDigest, digests.a);
    assert.equal(written.json.outcome, 'committed-verified');
    assert.deepEqual(written.json.rollback, { action: 'retract', expectCurrent: digests.a, approval: `RETRACT:${digests.a}`, backupRequired: true });
    const receipt = JSON.parse(await fs.readFile(path.join(dir, `receipt-${receipts}.json`), 'utf8'));
    assert.equal(receipt.status, 'COMMITTED_VERIFIED');
    assert.equal((await fs.stat(path.join(dir, `receipt-${receipts}.json`))).mode & 0o777, 0o600);

    const read = await clientRead(users.owner);
    assert.equal(read.status, 'ok');
    assert.equal(envelopeDigest(read.envelope), digests.a);
    const data = await decryptEnvelope(read.envelope, PASS);
    assert.equal(data.example, true);
    assert.equal(data.contacts.length, 4);
    await assert.rejects(decryptEnvelope(read.envelope, 'wrong-synthetic-passphrase'));

    // Not the owner: denied on the owner's path, nothing on their own.
    const otherSession = await signInGoogle(users.other.email, users.other.sub);
    const denied = await readPrivateDocument({ origin: `http://${firestoreHost}`, projectId: PROJECT, uid: users.owner.uid, token: otherSession.idToken });
    assert.equal(denied.status, 'denied');
    const own = await clientRead(users.other);
    assert.notEqual(own.status, 'ok');
  });

  test('replacing needs the live digest and a backup; retract and restore round-trip', async () => {
    const owner = { uid: users.owner.uid, confirmUid: users.owner.uid };
    const writeB = { ...owner, approval: `WRITE:${digests.b}` };
    assert.equal((await store(['write', '--input', files.b, '--expect-current', 'none', '--backup', files.backup1, '--apply'], writeB)).refusal, 'STORE_REFUSED STORE_CURRENT_MISMATCH');
    assert.equal((await store(['write', '--input', files.b, '--expect-current', digests.a, '--apply'], writeB)).refusal, 'STORE_REFUSED STORE_BACKUP_REQUIRED');
    assert.equal((await store(['write', '--input', files.a, '--expect-current', digests.a, '--backup', files.backup1, '--apply'], { ...owner, approval: `WRITE:${digests.a}` })).refusal, 'STORE_REFUSED STORE_ALREADY_CURRENT');

    const replaced = await store(['write', '--input', files.b, '--expect-current', digests.a, '--backup', files.backup1, '--apply'], writeB);
    assert.equal(replaced.status, 0, replaced.refusal);
    assert.equal(replaced.json.previousDigest, digests.a);
    assert.equal(replaced.json.liveDigest, digests.b);
    assert.equal((await fs.stat(files.backup1)).mode & 0o777, 0o600);
    assert.equal(envelopeDigest(JSON.parse(await fs.readFile(files.backup1, 'utf8'))), digests.a);
    assert.equal((await decryptEnvelope((await clientRead(users.owner)).envelope, PASS)).generatedAt, 'synthetic-second-build');

    const retracted = await store(['retract', '--expect-current', digests.b, '--backup', files.backup2, '--apply'], { ...owner, approval: `RETRACT:${digests.b}` });
    assert.equal(retracted.status, 0, retracted.refusal);
    assert.equal(retracted.json.liveDigest, null);
    assert.equal((await clientRead(users.owner)).status, 'missing');
    assert.equal((await store(['retract', '--expect-current', digests.b, '--backup', path.join(dir, 'b3.json'), '--apply'], { ...owner, approval: `RETRACT:${digests.b}` })).refusal, 'STORE_REFUSED STORE_NOTHING_TO_RETRACT');

    const restored = await store(['write', '--input', files.backup2, '--expect-current', 'none', '--apply'], writeB);
    assert.equal(restored.status, 0, restored.refusal);
    assert.equal(envelopeDigest((await clientRead(users.owner)).envelope), digests.b);
  });

  test('accounts without the owner claim cannot receive a write, and no output names an account', async () => {
    const id = { uid: users.other.uid, confirmUid: users.other.uid, approval: `WRITE:${digests.a}` };
    assert.equal((await store(['inspect'], id)).json.ownerEligible, false);
    assert.equal((await store(['write', '--input', files.a, '--expect-current', 'none', '--apply'], id)).refusal, 'STORE_REFUSED STORE_OWNER_NOT_ELIGIBLE');
    assert.equal((await store(['inspect'], { uid: 'noSuchSyntheticUid' })).refusal, 'STORE_REFUSED STORE_UNKNOWN_UID');
    const all = outputs.join('\n');
    for (const secret of [users.owner.uid, users.other.uid, users.owner.email, users.other.email, 'example.com', PASS]) {
      assert.ok(!all.includes(secret), 'tool output named an account or secret');
    }
  });
});
