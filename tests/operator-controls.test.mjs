// F4 credential provenance and identity binding, and the operator lock that
// coordinates Step D writes with D0 claim changes. Temporary directories,
// fictional identities and injected network/gcloud stand-ins only.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { refreshToken } from 'firebase-admin/app';
import { encryptEnvelope } from '../secure/envelope.mjs';
import { isCredentialEnvKey, PRODUCTION_PROJECT, StoreRefusal } from '../secure/campaign-store.mjs';
import { acquireOperatorLock } from '../secure/operator-lock.mjs';
import { syntheticPayload } from '../secure/synthetic-contacts.mjs';
import { bindOperatorIdentity, exitCodeFor, failureLine, loadOperatorCredential, main } from '../scripts/blitz-campaign-store.mjs';
import { runSyntheticOwnerAction } from '../scripts/d0-owner-emulator.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const USER_ADC = {
  account: '',
  client_id: 'synthetic-client.apps.googleusercontent.com',
  client_secret: 'synthetic-client-secret',
  quota_project_id: PRODUCTION_PROJECT,
  refresh_token: 'synthetic-refresh-token',
  type: 'authorized_user',
  universe_domain: 'googleapis.com',
};

async function tempDir(prefix) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), prefix));
  await fs.chmod(dir, 0o700);
  return dir;
}

async function writeAdc(home, body, mode = 0o600) {
  const dir = path.join(home, '.config', 'gcloud');
  await fs.mkdir(dir, { recursive: true });
  const file = path.join(dir, 'application_default_credentials.json');
  await fs.writeFile(file, typeof body === 'string' ? body : JSON.stringify(body), { mode });
  await fs.chmod(file, mode);
  return file;
}

async function refusalCode(promise) {
  try {
    await promise;
  } catch (error) {
    return error.code || error.message;
  }
  return 'NO_REFUSAL';
}

test('F4: only the operator\'s own gcloud user ADC file is accepted, from gcloud\'s config directory', async () => {
  const home = await tempDir('blitz-adc-home-');
  try {
    await writeAdc(home, USER_ADC);
    assert.deepEqual(await loadOperatorCredential({ env: {}, home, projectId: PRODUCTION_PROJECT }), USER_ADC);
    const config = await tempDir('blitz-adc-config-');
    try {
      await fs.writeFile(path.join(config, 'application_default_credentials.json'), JSON.stringify(USER_ADC), { mode: 0o600 });
      assert.deepEqual(await loadOperatorCredential({ env: { CLOUDSDK_CONFIG: config }, home: '/nonexistent', projectId: PRODUCTION_PROJECT }), USER_ADC);
    } finally {
      await fs.rm(config, { recursive: true, force: true });
    }
    assert.equal(await refusalCode(loadOperatorCredential({ env: { CLOUDSDK_CONFIG: 'relative/dir' }, home, projectId: PRODUCTION_PROJECT })), 'STORE_ADC_CONFIG_DIR');

    const cases = [
      [{ type: 'service_account', project_id: PRODUCTION_PROJECT, private_key: 'synthetic', client_email: 'sa@example.com' }, 'STORE_ADC_NOT_USER_CREDENTIAL'],
      [{ type: 'external_account', audience: 'x', subject_token_type: 'x', credential_source: { file: '/x' } }, 'STORE_ADC_NOT_USER_CREDENTIAL'],
      [{ type: 'impersonated_service_account', service_account_impersonation_url: 'https://x', source_credentials: USER_ADC }, 'STORE_ADC_NOT_USER_CREDENTIAL'],
      [{ ...USER_ADC, service_account_impersonation_url: 'https://iamcredentials.googleapis.com/x' }, 'STORE_ADC_UNEXPECTED_FIELDS'],
      [{ ...USER_ADC, quota_project_id: 'another-project' }, 'STORE_ADC_QUOTA_PROJECT'],
      [{ ...USER_ADC, quota_project_id: undefined }, 'STORE_ADC_QUOTA_PROJECT'],
      [{ ...USER_ADC, universe_domain: 'example.com' }, 'STORE_ADC_UNIVERSE'],
      [{ ...USER_ADC, refresh_token: '' }, 'STORE_ADC_UNREADABLE'],
      ['not json', 'STORE_ADC_UNREADABLE'],
    ];
    for (const [body, code] of cases) {
      await writeAdc(home, body);
      assert.equal(await refusalCode(loadOperatorCredential({ env: {}, home, projectId: PRODUCTION_PROJECT })), code, JSON.stringify(body).slice(0, 60));
    }
    await writeAdc(home, USER_ADC, 0o666);
    assert.equal(await refusalCode(loadOperatorCredential({ env: {}, home, projectId: PRODUCTION_PROJECT })), 'STORE_ADC_WRITABLE_BY_OTHERS');
    const real = path.join(home, 'elsewhere.json');
    await fs.writeFile(real, JSON.stringify(USER_ADC), { mode: 0o600 });
    const adc = path.join(home, '.config', 'gcloud', 'application_default_credentials.json');
    await fs.rm(adc);
    await fs.symlink(real, adc);
    assert.equal(await refusalCode(loadOperatorCredential({ env: {}, home, projectId: PRODUCTION_PROJECT })), 'STORE_ADC_NOT_REGULAR_FILE');
    await fs.rm(adc);
    assert.equal(await refusalCode(loadOperatorCredential({ env: {}, home, projectId: PRODUCTION_PROJECT })), 'STORE_ADC_MISSING');
  } finally {
    await fs.rm(home, { recursive: true, force: true });
  }
});

test('F4: a credential file inside the repository is refused', async () => {
  const inside = path.join(root, '..adc-boundary-test');
  try {
    await fs.mkdir(inside, { recursive: true });
    await fs.writeFile(path.join(inside, 'application_default_credentials.json'), JSON.stringify(USER_ADC), { mode: 0o600 });
    assert.equal(await refusalCode(loadOperatorCredential({ env: { CLOUDSDK_CONFIG: inside }, projectId: PRODUCTION_PROJECT })), 'STORE_ADC_INSIDE_REPOSITORY');
  } finally {
    await fs.rm(inside, { recursive: true, force: true });
  }
});

test('F4: the ADC account must be the active gcloud account; neither identity leaves the check', async () => {
  const calls = [];
  const credential = { getAccessToken: async () => ({ access_token: 'synthetic-access-token' }) };
  const fetchAs = (body, ok = true) => async (url, init) => {
    calls.push({ url, init });
    return { ok, json: async () => body };
  };
  assert.equal(await bindOperatorIdentity({ credential, fetchImpl: fetchAs({ email: 'operator@example.com', email_verified: 'true' }), gcloud: () => 'Operator@Example.com\n' }), true);
  assert.equal(calls[0].url, 'https://oauth2.googleapis.com/tokeninfo', 'the token is never placed in a URL');
  assert.equal(calls[0].init.method, 'POST');
  const cases = [
    [fetchAs({ email: 'someone-else@example.com', email_verified: 'true' }), () => 'operator@example.com', 'STORE_ADC_IDENTITY_MISMATCH'],
    [fetchAs({ email: 'operator@example.com', email_verified: 'false' }), () => 'operator@example.com', 'STORE_ADC_IDENTITY_UNAVAILABLE'],
    [fetchAs({}, false), () => 'operator@example.com', 'STORE_ADC_IDENTITY_UNAVAILABLE'],
    [fetchAs({ email: 'operator@example.com', email_verified: true }), () => '', 'STORE_GCLOUD_ACCOUNT_UNAVAILABLE'],
  ];
  for (const [fetchImpl, gcloud, code] of cases) {
    const error = await bindOperatorIdentity({ credential, fetchImpl, gcloud }).catch((e) => e);
    assert.ok(error instanceof StoreRefusal, code);
    assert.equal(error.code, code);
    assert.doesNotMatch(error.message, /@|synthetic-access-token/);
  }
  const broken = { getAccessToken: async () => { throw new Error('invalid_grant for operator@example.com'); } };
  const error = await bindOperatorIdentity({ credential: broken, fetchImpl: fetchAs({}), gcloud: () => 'x@example.com' }).catch((e) => e);
  assert.equal(error.code, 'STORE_ADC_IDENTITY_UNAVAILABLE');
  assert.doesNotMatch(error.message, /@/);
});

test('F4: production runs bind the checked credential before any SDK call and print no identity', async () => {
  const lockDir = await tempDir('blitz-lock-');
  try {
    const env = { BLITZ_STORE_UID: 'syntheticOwnerUid01', BLITZ_OPERATOR_LOCK_DIR: lockDir };
    const seen = [];
    const deps = {
      loadOperatorCredential: async ({ projectId }) => { seen.push(['load', projectId]); return USER_ADC; },
      bindOperatorIdentity: async ({ credential }) => {
        seen.push(['bind', typeof credential.getAccessToken]);
        throw new StoreRefusal('STORE_ADC_IDENTITY_MISMATCH');
      },
    };
    const args = ['inspect', '--target', 'production', '--project', PRODUCTION_PROJECT];
    assert.equal(await refusalCode(main(args, env, deps)), 'STORE_ADC_IDENTITY_MISMATCH');
    assert.deepEqual(seen, [['load', PRODUCTION_PROJECT], ['bind', 'function']]);
    // The checked file is what the SDK would receive: a refresh-token credential.
    assert.equal(typeof refreshToken(USER_ADC).getAccessToken, 'function');
    // A refused production run leaves no lock behind.
    const lock = await acquireOperatorLock({ project: PRODUCTION_PROJECT, purpose: 'test', dir: lockDir });
    await lock.release();
  } finally {
    await fs.rm(lockDir, { recursive: true, force: true });
  }
});

test('operator lock: exclusive per project, private, never broken by another holder', async () => {
  const dir = await tempDir('blitz-lock-');
  try {
    const first = await acquireOperatorLock({ project: 'demo-blitz-store', purpose: 'store-write', dir });
    assert.equal(await refusalCode(acquireOperatorLock({ project: 'demo-blitz-store', purpose: 'd0-grant', dir })), 'LOCK_HELD');
    const other = await acquireOperatorLock({ project: 'demo-other-project', purpose: 'd0-grant', dir });
    await other.release();
    assert.equal(((await fs.stat(first.file)).mode & 0o777), 0o600);
    await first.release();
    const second = await acquireOperatorLock({ project: 'demo-blitz-store', purpose: 'store-write', dir });
    // A stale holder's release does not remove a newer holder's lock.
    await first.release();
    assert.equal(await refusalCode(acquireOperatorLock({ project: 'demo-blitz-store', purpose: 'store-write', dir })), 'LOCK_HELD');
    await second.release();
    await fs.chmod(dir, 0o755);
    assert.equal(await refusalCode(acquireOperatorLock({ project: 'demo-blitz-store', purpose: 'x', dir })), 'LOCK_DIRECTORY_NOT_PRIVATE');
    await fs.chmod(dir, 0o700);
    assert.equal(await refusalCode(acquireOperatorLock({ project: '../x', purpose: 'x', dir })), 'LOCK_INVALID_PROJECT');
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

function cleanEnv(extra) {
  const env = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (/^(BLITZ_|FIRESTORE_EMULATOR_HOST|FIREBASE_AUTH_EMULATOR_HOST|CI$|GITHUB_ACTIONS)|PASSPHRASE/i.test(key) || isCredentialEnvKey(key)) continue;
    env[key] = value;
  }
  return { ...env, ...extra };
}

test('claim race control: a store apply refuses while a claim change holds the lock, before writing anything', async () => {
  const dir = await tempDir('blitz-store-lock-');
  const lockDir = path.join(dir, 'locks');
  try {
    const input = path.join(dir, 'synthetic.json');
    await fs.writeFile(input, JSON.stringify(await encryptEnvelope(syntheticPayload(), 'synthetic-lock-passphrase')));
    const held = await acquireOperatorLock({ project: 'demo-blitz-store', purpose: 'd0-grant', dir: lockDir });
    try {
      const result = spawnSync(process.execPath, [
        'scripts/blitz-campaign-store.mjs', 'write', '--target', 'emulator', '--project', 'demo-blitz-store',
        '--input', input, '--expect-current', 'none', '--receipt', path.join(dir, 'receipt.json'), '--apply',
      ], {
        cwd: root, encoding: 'utf8', timeout: 20000,
        env: cleanEnv({ FIRESTORE_EMULATOR_HOST: '127.0.0.1:9', FIREBASE_AUTH_EMULATOR_HOST: '127.0.0.1:9', BLITZ_STORE_UID: 'syntheticOwnerUid01', BLITZ_OPERATOR_LOCK_DIR: lockDir }),
      });
      assert.equal(result.status, 1);
      assert.equal(result.stderr.trim(), 'STORE_REFUSED STORE_OPERATOR_LOCK_HELD');
      await assert.rejects(fs.access(path.join(dir, 'receipt.json')));
    } finally {
      await held.release();
    }
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test('claim race control: the D0 claim tool takes the same lock, and refuses lower-case credential variables', async () => {
  const lockDir = await tempDir('blitz-d0-lock-');
  const saved = { ...process.env };
  try {
    for (const key of Object.keys(process.env)) if (isCredentialEnvKey(key)) delete process.env[key];
    process.env.FIREBASE_AUTH_EMULATOR_HOST = '127.0.0.1:9';
    process.env.BLITZ_OPERATOR_LOCK_DIR = lockDir;
    const options = { projectId: 'demo-blitz-secure', uid: 'synthetic-owner', action: 'grant', apply: true, confirmUid: 'synthetic-owner', approval: 'APPLY_SYNTHETIC_ONLY' };
    const held = await acquireOperatorLock({ project: 'demo-blitz-secure', purpose: 'store-write', dir: lockDir });
    try {
      await assert.rejects(runSyntheticOwnerAction(options), /D0_OPERATOR_LOCK_HELD/);
    } finally {
      await held.release();
    }
    process.env.google_application_credentials = '/synthetic/credential.json';
    await assert.rejects(runSyntheticOwnerAction(options), /D0_CREDENTIAL_ENV_REFUSED/);
  } finally {
    for (const key of Object.keys(process.env)) if (!(key in saved)) delete process.env[key];
    Object.assign(process.env, saved);
    await fs.rm(lockDir, { recursive: true, force: true });
  }
});

test('operator lock: a lock directory inside the repository is refused before anything is created', async () => {
  for (const inside of [path.join(root, '..locks'), path.join(root, 'docs', 'locks')]) {
    assert.equal(await refusalCode(acquireOperatorLock({ project: 'demo-blitz-store', purpose: 'x', dir: inside })), 'LOCK_DIRECTORY_INSIDE_REPOSITORY');
    await assert.rejects(fs.access(inside), undefined, inside);
  }
});

test('only exit 1 means nothing was written; other outcomes are reported as unresolved', () => {
  const refused = Object.assign(new StoreRefusal('STORE_CONCURRENT_CHANGE'), { outcome: 'refused-before-write' });
  const unknown = Object.assign(new StoreRefusal('STORE_OUTCOME_UNKNOWN'), { outcome: 'unknown' });
  const drift = Object.assign(new StoreRefusal('STORE_ELIGIBILITY_CHANGED_DURING_COMMIT'), { outcome: 'committed-eligibility-changed' });
  const late = Object.assign(new StoreRefusal('STORE_RECEIPT_FAILED_AFTER_COMMIT'), { outcome: 'committed-verified' });
  assert.deepEqual([refused, unknown, drift, late].map(exitCodeFor), [1, 3, 4, 5]);
  assert.equal(failureLine(refused), 'STORE_REFUSED STORE_CONCURRENT_CHANGE');
  assert.equal(failureLine(new StoreRefusal('STORE_APPROVAL_REQUIRED')), 'STORE_REFUSED STORE_APPROVAL_REQUIRED');
  assert.equal(failureLine(unknown), 'STORE_UNRESOLVED STORE_OUTCOME_UNKNOWN');
  assert.equal(failureLine(drift), 'STORE_UNRESOLVED STORE_ELIGIBILITY_CHANGED_DURING_COMMIT');
  assert.equal(failureLine(late), 'STORE_UNRESOLVED STORE_RECEIPT_FAILED_AFTER_COMMIT');
});
