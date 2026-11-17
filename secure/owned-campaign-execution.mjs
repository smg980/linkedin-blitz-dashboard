// Internal trusted worker implementation. Never accept factories or callbacks
// from an ordinary IPC request. The protected supervisor owns admission.
import { SettledExecutor } from './settled-executor.mjs';
import { runStoreAction, StoreRefusal } from './campaign-store.mjs';
import { createEmulatorFirestore, createOperatorClients } from './operator-clients.mjs';

export async function runOwnedCampaign({ opts, env, deps, input, uid, writers,
  backupPath, receiptPath, loadCredential, bindIdentity }) {
  const executor = new SettledExecutor({
    admission: { async acquire() {}, async release() {},
      async clean() { deps.executorSession.settled(); } },
    openClients: async () => {
      deps.executorSession.started();
      const admin = await import('firebase-admin/app');
      const { getAuth } = await import('firebase-admin/auth');
      let firestore;
      let app;
      try {
        let appOptions = { projectId: opts.project };
        if (opts.target === 'production') {
          const adc = await (deps.loadOperatorCredential || loadCredential)({ env, projectId: opts.project });
          const clients = createOperatorClients({ adc, projectId: opts.project, testTransport: deps.testTransport });
          firestore = clients.firestore;
          await (deps.bindOperatorIdentity || bindIdentity)({ credential: clients.credential });
          appOptions = { projectId: opts.project, credential: clients.credential };
          if (deps.testTransport?.httpAgent) appOptions.httpAgent = deps.testTransport.httpAgent;
        } else {
          firestore = createEmulatorFirestore({ projectId: opts.project });
        }
        app = admin.initializeApp(appOptions, `blitz-executor-${process.pid}-${Date.now()}`);
        return { firestore, auth: getAuth(app), deleteApp: () => admin.deleteApp(app) };
      } catch (error) {
        // Failure to open a client never produces settlement authority.
        try { if (firestore) await firestore.terminate(); } catch {}
        try { if (app) await admin.deleteApp(app); } catch {}
        throw error;
      }
    },
  });
  const completion = await executor.run(async ({ db, auth }) => {
    const result = await runStoreAction({
      db, auth, backup: writers.backup, receipt: writers.receipt,
      target: opts.target, projectId: opts.project, action: opts.action, uid,
      confirmUid: env.BLITZ_STORE_CONFIRM_UID, approval: env.BLITZ_STORE_APPROVAL,
      input: input?.envelope ?? null, expectCurrent: opts.expectCurrent,
      backupPath, receiptPath, apply: opts.apply,
    });
    return { target: opts.target, ...result,
      ...(opts.target === 'production' ? { operatorIdentityBound: true } : {}),
      ...(input ? { inputFileSha256: input.fileSha256 } : {}) };
  });
  const metadata = completion.cleanupComplete ? {} : {
    cleanupComplete: false, cleanupFailures: completion.cleanupFailures,
  };
  if (completion.error !== undefined) {
    const error = completion.error instanceof StoreRefusal ? completion.error : new StoreRefusal('STORE_OPERATION_FAILED');
    Object.assign(error, metadata);
    throw error;
  }
  return { ...completion.result, ...metadata };
}
