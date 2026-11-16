import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { planOwnerAction } from '../scripts/d0-owner-emulator.mjs';

const fixture = (overrides = {}) => ({
  uid: 'synthetic-owner', email: 'owner-synthetic@example.com', disabled: false,
  emailVerified: true, providerData: [{ providerId: 'google.com' }],
  customClaims: { otherFeature: 'preserved' }, ...overrides,
});
const approved = { uid: 'synthetic-owner', action: 'grant', apply: true,
  confirmUid: 'synthetic-owner', approval: 'APPLY_SYNTHETIC_ONLY' };

test('D0 defaults to read-only inspection and preserves unrelated claims', () => {
  const user = fixture();
  const before = structuredClone(user);
  const plan = planOwnerAction(user, { uid: user.uid });
  assert.equal(plan.owner, false);
  assert.deepEqual(plan.next, user.customClaims);
  assert.deepEqual(user, before);
  assert.deepEqual(planOwnerAction(user, approved).next, { otherFeature: 'preserved', blitzOwner: true });
});

test('D0 grants require a verified enabled Google account and exact identity', () => {
  for (const overrides of [{ emailVerified: false }, { disabled: true }, { providerData: [] },
    { providerData: [{ providerId: 'password' }] }, { uid: 'different-synthetic-user' },
    { email: 'synthetic@invalid.test' }]) {
    assert.throws(() => planOwnerAction(fixture(overrides), approved));
  }
});

test('D0 apply requires exact confirmation and explicit approval; inspect cannot write', () => {
  for (const overrides of [{ confirmUid: undefined }, { confirmUid: 'wrong-uid' },
    { approval: undefined }, { approval: true }, { action: 'inspect' }, { action: 'typo' }, { uid: '../uid' }]) {
    assert.throws(() => planOwnerAction(fixture(), { ...approved, ...overrides }));
  }
});

test('D0 revoke removes only blitzOwner and remains possible for disabled/unverified users', () => {
  const user = fixture({ disabled: true, emailVerified: false,
    customClaims: { otherFeature: 'preserved', blitzOwner: true } });
  const revoked = planOwnerAction(user, { ...approved, action: 'revoke' });
  assert.deepEqual(revoked.next, { otherFeature: 'preserved' });
  assert.deepEqual(planOwnerAction(fixture({ customClaims: revoked.next }), { ...approved, action: 'revoke' }).next, revoked.next);
  for (const value of ['true', 1, false, null]) {
    assert.equal(planOwnerAction(fixture({ customClaims: { blitzOwner: value } }), { uid: user.uid }).owner, false);
  }
});

test('D0 CLI refuses production, missing/remote emulators, credentials and unknown flags without identity leakage', () => {
  for (const extra of [
    { FIREBASE_AUTH_EMULATOR_HOST: '' },
    { FIREBASE_AUTH_EMULATOR_HOST: 'identitytoolkit.googleapis.com:443' },
    { FIREBASE_AUTH_EMULATOR_HOST: '127.0.0.1:0' },
    { FIREBASE_AUTH_EMULATOR_HOST: '127.0.0.1:9099', BLITZ_D0_PROJECT: 'master-intelligence-5496f' },
    { FIREBASE_AUTH_EMULATOR_HOST: '127.0.0.1:9099', GOOGLE_APPLICATION_CREDENTIALS: '/synthetic/credential.json' },
  ]) {
    const env = { ...process.env, BLITZ_D0_SYNTHETIC_UID: 'synthetic-private-uid', ...extra };
    const result = spawnSync(process.execPath, ['scripts/d0-owner-emulator.mjs', '--grant', '--apply'], { encoding: 'utf8', env });
    assert.equal(result.status, 1);
    assert.doesNotMatch(result.stdout + result.stderr, /synthetic-private-uid|credential\.json|master-intelligence/);
    assert.match(result.stderr, /D0_REFUSED/);
  }
  const unknown = spawnSync(process.execPath, ['scripts/d0-owner-emulator.mjs', '--production'], { encoding: 'utf8' });
  assert.equal(unknown.status, 1);
});
