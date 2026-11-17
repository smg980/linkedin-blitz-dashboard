import { isDeepStrictEqual } from 'node:util';
import { SettledExecutor } from './settled-executor.mjs';
import { oneAttemptEmulatorClaims, assertEmulatorClaims } from './one-attempt-emulator-claims.mjs';
import { StoreRefusal } from './campaign-store.mjs';

export async function runOwnedD0(options, session, planOwnerAction) {
  const executor = new SettledExecutor({
    admission: { async acquire() {}, async release() {}, async clean() { session.settled(); } },
    openClients: async () => {
      session.started();
      const admin = await import('firebase-admin/app');
      const { getAuth } = await import('firebase-admin/auth');
      const app = admin.initializeApp({ projectId: options.projectId }, `d0-executor-${process.pid}-${Date.now()}`);
      const auth = getAuth(app);
      const writes = oneAttemptEmulatorClaims({ projectId: options.projectId,
        host: process.env.FIREBASE_AUTH_EMULATOR_HOST });
      return { firestore: { async terminate() {} }, auth: {
        getUser: (uid) => auth.getUser(uid),
        setCustomUserClaims: writes.setCustomUserClaims,
        revokeRefreshTokens: writes.revokeRefreshTokens,
      }, deleteApp: async () => { await writes.shutdown(); await admin.deleteApp(app); } };
    },
  });
  const check = (value) => { if (!value) throw new Error('D0_EXECUTOR_VERIFICATION_FAILED'); };
  const completion = await executor.run(async ({ auth }) => {
    const planFor = (user) => {
      try { return planOwnerAction(user, options); }
      catch (error) {
        const code = /^D0_[A-Z_]{1,50}$/.test(error?.message || '') ? error.message : 'D0_PRE_WRITE_REFUSED';
        throw Object.assign(new StoreRefusal(code), { outcome: 'refused-before-write' });
      }
    };
    const user = await auth.getUser(options.uid);
    const plan = planFor(user);
    const latest = await auth.getUser(options.uid);
    const rechecked = planFor(latest);
    if (!isDeepStrictEqual(rechecked.current, plan.current)) {
      throw Object.assign(new StoreRefusal('D0_CONCURRENT_CLAIM_CHANGE'), { outcome: 'refused-before-write' });
    }
    try { assertEmulatorClaims(rechecked.next); }
    catch { throw Object.assign(new StoreRefusal('D0_CLAIMS_INVALID'), { outcome: 'refused-before-write' }); }
    await auth.setCustomUserClaims(options.uid, rechecked.next);
    const revokeStarted = Math.floor(Date.now() / 1000) * 1000;
    if (options.action === 'revoke') await auth.revokeRefreshTokens(options.uid);
    const verified = await auth.getUser(options.uid);
    check(verified.uid === options.uid && isDeepStrictEqual(verified.customClaims || {}, rechecked.next));
    if (options.action === 'revoke') check(Date.parse(verified.tokensValidAfterTime) >= revokeStarted);
    return { dryRun: false, verified: true, owner: verified.customClaims?.blitzOwner === true,
      outcome: 'committed-verified' };
  });
  if (completion.error) {
    const preWrite = completion.error instanceof StoreRefusal && completion.error.outcome === 'refused-before-write';
    const code = preWrite ? completion.error.code : 'D0_EMULATOR_OPERATION_FAILED';
    const error = Object.assign(new Error(code), { code,
      outcome: preWrite ? 'refused-before-write' : 'unknown',
      ...(completion.cleanupComplete ? {} : { cleanupComplete: false, cleanupFailures: completion.cleanupFailures }) });
    throw error;
  }
  return { ...completion.result, ...(completion.cleanupComplete ? {} : {
    cleanupComplete: false, cleanupFailures: completion.cleanupFailures }) };
}
