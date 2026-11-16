#!/usr/bin/env node
// D0 rehearsal only. There is deliberately no production mode or ADC fallback.
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { isDeepStrictEqual } from 'node:util';
import { credentialEnvPresent } from '../secure/campaign-store.mjs';
import { assertEmulatorTarget } from '../secure/emulator-guard.mjs';
import { acquireOperatorLock, lockDirectory } from '../secure/operator-lock.mjs';

function requireValue(condition, code) {
  if (!condition) throw new Error(code);
}

export function planOwnerAction(user, { uid, action = 'inspect', apply = false, confirmUid, approval } = {}) {
  requireValue(typeof apply === 'boolean', 'D0_INVALID_APPLY');
  requireValue(/^[A-Za-z0-9_-]{1,128}$/.test(uid || ''), 'D0_INVALID_UID');
  requireValue(['inspect', 'grant', 'revoke'].includes(action), 'D0_INVALID_ACTION');
  requireValue(user?.uid === uid, 'D0_UID_MISMATCH');
  // Even a local emulator accidentally populated with real identities is refused.
  requireValue(/^[^@\s]+@example\.com$/.test(user.email || ''), 'D0_SYNTHETIC_ACCOUNT_REQUIRED');
  const eligible = user.disabled === false && user.emailVerified === true
    && user.providerData?.some((provider) => provider.providerId === 'google.com') === true;
  if (action === 'grant') requireValue(eligible, 'D0_INELIGIBLE_ACCOUNT');
  if (apply) {
    requireValue(action !== 'inspect', 'D0_INSPECT_IS_READ_ONLY');
    requireValue(approval === 'APPLY_SYNTHETIC_ONLY', 'D0_APPROVAL_REQUIRED');
    requireValue(confirmUid === uid, 'D0_EXACT_UID_CONFIRMATION_REQUIRED');
  }
  const current = { ...(user.customClaims || {}) };
  const next = { ...current };
  if (action === 'grant') next.blitzOwner = true;
  if (action === 'revoke') delete next.blitzOwner;
  return { eligible, owner: current.blitzOwner === true, next, current };
}

export async function runSyntheticOwnerAction(options = {}) {
  const { projectId = 'demo-blitz-secure', uid, action = 'inspect', apply = false } = options;
  // Validate before loading Admin SDK, resolving credentials, or doing network I/O.
  const host = process.env.FIREBASE_AUTH_EMULATOR_HOST;
  requireValue(/^(127\.0\.0\.1|localhost):[0-9]+$/.test(host || ''), 'D0_LOOPBACK_AUTH_REQUIRED');
  assertEmulatorTarget({ host, projectId });
  // F4: every spelling of a credential override, not only the upper-case one.
  requireValue(!credentialEnvPresent(process.env) && !process.env.DASHBOARD_PASSPHRASE, 'D0_CREDENTIAL_ENV_REFUSED');
  requireValue(/^[A-Za-z0-9_-]{1,128}$/.test(uid || ''), 'D0_INVALID_UID');
  requireValue(['inspect', 'grant', 'revoke'].includes(action), 'D0_INVALID_ACTION');
  // Claim race: a claim change holds the same per-project operator lock as a
  // Step D store run, so the two never overlap.
  let lock = null;
  if (apply) {
    try {
      lock = await acquireOperatorLock({ project: projectId, purpose: `d0-${action}`, dir: lockDirectory() });
    } catch {
      throw new Error('D0_OPERATOR_LOCK_HELD');
    }
  }
  let app;
  let deleteApp;
  try {
    const admin = await import('firebase-admin/app');
    deleteApp = admin.deleteApp;
    const { getAuth } = await import('firebase-admin/auth');
    app = admin.initializeApp({ projectId }, `d0-${process.pid}-${Date.now()}`);
    const auth = getAuth(app);
    const user = await auth.getUser(uid); // Exact lookup only; never exports/listUsers.
    const plan = planOwnerAction(user, options);
    if (!apply) return { dryRun: true, eligible: plan.eligible, owner: plan.owner };
    // Re-read to catch ordinary concurrent operator edits. This is not a CAS;
    // the runbook requires one operator and no concurrent claim writers.
    const latest = await auth.getUser(uid);
    const rechecked = planOwnerAction(latest, options);
    requireValue(isDeepStrictEqual(rechecked.current, plan.current), 'D0_CONCURRENT_CLAIM_CHANGE');
    await auth.setCustomUserClaims(uid, rechecked.next);
    const revokeStarted = Math.floor(Date.now() / 1000) * 1000;
    if (action === 'revoke') await auth.revokeRefreshTokens(uid);
    const verified = await auth.getUser(uid);
    requireValue(verified.uid === uid, 'D0_UID_MISMATCH');
    requireValue(isDeepStrictEqual(verified.customClaims || {}, rechecked.next), 'D0_CLAIM_VERIFICATION_FAILED');
    if (action === 'revoke') requireValue(Date.parse(verified.tokensValidAfterTime) >= revokeStarted, 'D0_REVOCATION_VERIFICATION_FAILED');
    return { dryRun: false, verified: true, owner: verified.customClaims?.blitzOwner === true };
  } catch {
    // SDK errors can contain emails, UIDs or remote response bodies. Never print them.
    throw new Error('D0_EMULATOR_OPERATION_FAILED');
  } finally {
    if (app) await deleteApp(app);
    if (lock) await lock.release();
  }
}

async function main() {
  const args = process.argv.slice(2);
  requireValue(args.every((arg) => ['--inspect', '--grant', '--revoke', '--apply'].includes(arg))
    && new Set(args).size === args.length, 'D0_INVALID_ARGUMENTS');
  const actions = args.filter((arg) => arg !== '--apply');
  requireValue(actions.length <= 1, 'D0_INVALID_ACTION');
  const result = await runSyntheticOwnerAction({
    projectId: process.env.BLITZ_D0_PROJECT || 'demo-blitz-secure',
    uid: process.env.BLITZ_D0_SYNTHETIC_UID,
    confirmUid: process.env.BLITZ_D0_CONFIRM_UID,
    approval: process.env.BLITZ_D0_APPROVAL,
    action: actions[0]?.slice(2) || 'inspect',
    apply: args.includes('--apply'),
  });
  console.log(JSON.stringify(result)); // Only booleans, never account details/claims/tokens.
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(() => {
    console.error('D0_REFUSED: check the synthetic-only runbook; no account details are logged.');
    process.exitCode = 1;
  });
}
