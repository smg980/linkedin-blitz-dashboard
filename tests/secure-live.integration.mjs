import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { before, describe, test } from 'node:test';
import { DEMO_PASSPHRASE } from '../scripts/build-firebase-demo.mjs';
import { checkSecureShell } from '../scripts/secure-browser-check.mjs';
import { decryptEnvelope } from '../secure/envelope.mjs';
import { assertEmulatorTarget } from '../secure/emulator-guard.mjs';
import { envelopeFromFirestoreFields } from '../secure/firestore-get.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PROJECT = 'demo-blitz-secure';
const OWNER_EMAIL = 'owner-synthetic@example.com';
const INTRUDER_EMAIL = 'intruder-synthetic@example.com';
const firestoreHost = process.env.FIRESTORE_EMULATOR_HOST;
const authHost = process.env.FIREBASE_AUTH_EMULATOR_HOST;
assert.ok(firestoreHost && authHost, 'Auth and Firestore emulator hosts are required');
assertEmulatorTarget({ host: firestoreHost, projectId: PROJECT });
if (!/^(127\.0\.0\.1|localhost):\d+$/.test(authHost)) throw new Error('Auth emulator host is not loopback');

const users = {};

function cleanEnv(extra = {}) {
  const env = { ...process.env, ...extra };
  delete env.DASHBOARD_PASSPHRASE;
  delete env.GOOGLE_APPLICATION_CREDENTIALS;
  delete env.FIREBASE_TOKEN;
  return env;
}

async function createGoogleUser(email, sub, name) {
  const claims = { sub, email, email_verified: true, name };
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
  assert.equal(response.status, 200, 'Auth emulator rejected a synthetic Google user');
  assert.ok(body.localId && body.idToken);
  return { uid: body.localId, idToken: body.idToken, email };
}

async function grantOwnerClaim(uid) {
  const response = await fetch(`http://${authHost}/identitytoolkit.googleapis.com/v1/accounts:update`, {
    method: 'POST',
    headers: { Authorization: 'Bearer owner', 'Content-Type': 'application/json' },
    body: JSON.stringify({ localId: uid, customAttributes: JSON.stringify({ blitzOwner: true }) }),
  });
  assert.equal(response.status, 200, 'Auth emulator did not set the synthetic owner claim');
}

function tokenPayload(idToken) {
  return JSON.parse(Buffer.from(idToken.split('.')[1], 'base64url').toString('utf8'));
}

function docUrl(uid) {
  return `http://${firestoreHost}/v1/projects/${PROJECT}/databases/(default)/documents/blitzOwners/${uid}/campaign/current`;
}

describe('private shell emulators', { concurrency: false }, () => {
  before(async () => {
    users.owner = await createGoogleUser(OWNER_EMAIL, 'synthetic-owner-sub-001', 'Synthetic Owner');
    users.intruder = await createGoogleUser(INTRUDER_EMAIL, 'synthetic-intruder-sub-001', 'Synthetic Intruder');
    await grantOwnerClaim(users.owner.uid);
    const claimed = await createGoogleUser(OWNER_EMAIL, 'synthetic-owner-sub-001', 'Synthetic Owner');
    assert.equal(claimed.uid, users.owner.uid);
    users.owner.idToken = claimed.idToken;
    const ownerToken = tokenPayload(users.owner.idToken);
    const intruderToken = tokenPayload(users.intruder.idToken);
    assert.equal(ownerToken.blitzOwner, true);
    assert.equal(ownerToken.email_verified, true);
    assert.equal(ownerToken.firebase.sign_in_provider, 'google.com');
    assert.notEqual(intruderToken.blitzOwner, true);
    assert.equal(intruderToken.email_verified, true);
    assert.equal(intruderToken.firebase.sign_in_provider, 'google.com');
    const ingested = spawnSync(process.execPath, [
      path.join(root, 'scripts', 'ingest-synthetic-emulator.mjs'),
      '--project', PROJECT,
      '--uid', users.owner.uid,
    ], {
      cwd: root,
      encoding: 'utf8',
      env: cleanEnv({ BLITZ_SYNTHETIC_PASSPHRASE: DEMO_PASSPHRASE }),
    });
    assert.equal(ingested.status, 0, ingested.stderr || ingested.stdout);
    const built = spawnSync(process.execPath, [
      path.join(root, 'scripts', 'build-secure-shell.mjs'),
      '--emulator',
    ], { cwd: root, encoding: 'utf8', env: cleanEnv() });
    assert.equal(built.status, 0, built.stderr || built.stdout);
  }, { timeout: 180000 });

  test('owner with the claim can read their encrypted document', async () => {
    const response = await fetch(docUrl(users.owner.uid), { headers: { Authorization: `Bearer ${users.owner.idToken}` } });
    assert.equal(response.status, 200);
    const raw = await response.text();
    assert.doesNotMatch(raw, /Example Ada|EXAMPLE Acme|EXAMPLE Globex/);
    const envelope = envelopeFromFirestoreFields(JSON.parse(raw).fields);
    const data = await decryptEnvelope(envelope, DEMO_PASSPHRASE);
    assert.deepEqual(data.contacts.map((item) => item.contact), ['Example Ada', 'Example Ben', 'Example Cy', 'Example Di']);
    assert.equal(data.example, true);
  });

  test('a verified Google user without the claim is denied on their own path', async () => {
    const response = await fetch(docUrl(users.intruder.uid), { headers: { Authorization: `Bearer ${users.intruder.idToken}` } });
    assert.equal(response.status, 403);
  });

  test('a claim holder cannot read another uid path', async () => {
    const response = await fetch(docUrl(users.intruder.uid), { headers: { Authorization: `Bearer ${users.owner.idToken}` } });
    assert.equal(response.status, 403);
  });

  test('a signed-out read is denied', async () => {
    const response = await fetch(docUrl(users.owner.uid));
    assert.ok(response.status === 401 || response.status === 403, 'signed-out status ' + response.status);
  });

  test('listing the private collection is denied', async () => {
    const headers = { Authorization: `Bearer ${users.owner.idToken}` };
    const rootList = await fetch(`http://${firestoreHost}/v1/projects/${PROJECT}/databases/(default)/documents/blitzOwners`, { headers });
    const campaignList = await fetch(`http://${firestoreHost}/v1/projects/${PROJECT}/databases/(default)/documents/blitzOwners/${users.owner.uid}/campaign`, { headers });
    assert.equal(rootList.status, 403);
    assert.equal(campaignList.status, 403);
  });

  test('client writes are denied', async () => {
    const response = await fetch(docUrl(users.owner.uid) + '?updateMask.fieldPaths=alg', {
      method: 'PATCH',
      headers: {
        Authorization: `Bearer ${users.owner.idToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ fields: { alg: { stringValue: 'nope' } } }),
    });
    assert.equal(response.status, 403);
  });

  test('built shell states fit an iPhone viewport', async () => {
    const result = await checkSecureShell({
      shellDir: path.join(root, '.firebase-blitz-private-shell'),
      passphrase: DEMO_PASSPHRASE,
      artifactsDir: process.env.BLITZ_SECURE_ARTIFACTS || '/opt/cursor/artifacts',
      ownerEmail: OWNER_EMAIL,
      intruderEmail: INTRUDER_EMAIL,
    });
    assert.ok(result.states.includes('signed-out'));
    assert.ok(result.states.includes('signing-in'));
    assert.ok(result.states.includes('not-authorized'));
    assert.ok(result.states.includes('locked'));
    assert.ok(result.states.includes('wrong-passphrase'));
    assert.ok(result.states.includes('unlocked'));
    assert.ok(result.states.includes('iphone-redirect'));
  });
});
