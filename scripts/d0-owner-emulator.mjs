#!/usr/bin/env node
// D0 rehearsal only. There is deliberately no production mode or ADC fallback.
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { isDeepStrictEqual } from 'node:util';
import { credentialEnvPresent } from '../secure/campaign-store.mjs';
import { assertEmulatorTarget } from '../secure/emulator-guard.mjs';

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

export async function runSyntheticOwnerAction(options = {}, deps = {}) {
  const { projectId = 'demo-blitz-secure', uid, action = 'inspect', apply = false } = options;
  requireValue(typeof apply === 'boolean', 'D0_INVALID_APPLY');
  // Validate before loading Admin SDK, resolving credentials, or doing network I/O.
  const policyEnv = deps.env || process.env;
  const host = policyEnv.FIREBASE_AUTH_EMULATOR_HOST;
  requireValue(/^(127\.0\.0\.1|localhost):[0-9]+$/.test(host || ''), 'D0_LOOPBACK_AUTH_REQUIRED');
  assertEmulatorTarget({ host, projectId });
  // F4: every spelling of a credential override, not only the upper-case one.
  requireValue(!credentialEnvPresent(policyEnv) && !policyEnv.DASHBOARD_PASSPHRASE, 'D0_CREDENTIAL_ENV_REFUSED');
  requireValue(/^[A-Za-z0-9_-]{1,128}$/.test(uid || ''), 'D0_INVALID_UID');
  requireValue(['inspect', 'grant', 'revoke'].includes(action), 'D0_INVALID_ACTION');
  if (apply) {
    requireValue(action !== 'inspect', 'D0_INSPECT_IS_READ_ONLY');
    requireValue(options.approval === 'APPLY_SYNTHETIC_ONLY', 'D0_APPROVAL_REQUIRED');
    requireValue(options.confirmUid === uid, 'D0_EXACT_UID_CONFIRMATION_REQUIRED');
  }
  if (apply && deps.executorSession) {
    const { runOwnedD0 } = await import('../secure/owned-d0-execution.mjs');
    return runOwnedD0({ ...options, projectId, uid, action, apply }, deps.executorSession, planOwnerAction);
  }
  if (apply) {
    const { requestExecutor } = await import('../secure/executor-client.mjs');
    const response = await requestExecutor('d0', [`--${action}`, '--apply'], {
      ...process.env, BLITZ_D0_PROJECT: projectId, BLITZ_D0_SYNTHETIC_UID: uid,
      BLITZ_D0_CONFIRM_UID: options.confirmUid, BLITZ_D0_APPROVAL: options.approval,
    });
    if (response.error) throw Object.assign(new Error(response.error.code), response.error, {
      quarantine: response.quarantine, cleanupComplete: response.cleanupComplete !== false });
    return { ...response.result, quarantine: response.quarantine,
      ...(response.cleanupComplete === false ? { cleanupComplete: false } : {}) };
  }
  // All apply paths returned through the executor above. The remaining code
  // is read-only and never takes the obsolete path-based operator lock.
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
  if (result.cleanupComplete === false) {
    console.error(`D0_CLEANUP_INCOMPLETE QUARANTINE=${result.quarantine || 'ACTIVE_OR_UNCONFIRMED'}`);
    process.exitCode = 10;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    const code = error?.code || error?.message || '';
    const fixed = /^[A-Z][A-Z0-9_]{1,63}$/.test(code) ? code : 'D0_OPERATION_FAILED';
    const quarantine = ['CLEAN', 'ACTIVE', 'ACTIVE_OR_UNCONFIRMED'].includes(error?.quarantine)
      ? error.quarantine : (error?.outcome === 'unknown' ? 'ACTIVE_OR_UNCONFIRMED' : null);
    console.error(`${error?.outcome === 'unknown' ? 'D0_UNRESOLVED' : 'D0_REFUSED'} ${fixed}${quarantine ? ` QUARANTINE=${quarantine}` : ''}`);
    if (error?.cleanupComplete === false) console.error('D0_CLEANUP_INCOMPLETE');
    process.exitCode = (error?.outcome === 'unknown' ? 3 : 1) + (error?.cleanupComplete === false ? 10 : 0);
  });
}
