// Internal trusted-executor primitive, not a client-facing service or API.
// Factories/task are fixed trusted code, never supplied over IPC or from argv.
// An integration must keep the raw clients and clean capability in this process.
import { StoreRefusal } from './campaign-store.mjs';
export class SettledExecutor {
  #state = 'new';
  #pending = 0;
  #rejected = false;
  #mutation = false;
  #admission;
  #open;

  constructor({ admission, openClients }) {
    this.#admission = admission;
    this.#open = openClients;
  }

  async run(task) {
    if (this.#state !== 'new') throw new Error('EXECUTOR_USED');
    this.#state = 'admitting';
    await this.#admission.acquire(); // must durably persist ACTIVE
    this.#state = 'running';
    let clients;
    let result;
    let error;
    const failures = [];
    const refs = new WeakMap();
    const check = () => {
      if (this.#state !== 'running') throw new Error('EXECUTOR_SEALED');
    };
    const request = async (fn, readOnly = false) => {
      check();
      this.#pending++;
      try { return await fn(); }
      catch (error) {
        // Auth's authoritative USER_NOT_FOUND response is a settled read,
        // unlike a lost connection/timeout. It cannot conceal a claim write.
        if (!(readOnly && error?.code === 'auth/user-not-found')) this.#rejected = true;
        throw error;
      }
      finally { this.#pending--; }
    };
    const snapshot = (raw) => {
      const value = raw.exists ? structuredClone(raw.data()) : undefined;
      return Object.freeze({ exists: raw.exists, data: () => structuredClone(value) });
    };
    try {
      clients = await this.#open();
      const db = Object.freeze({
        doc: (path) => {
          check();
          const raw = clients.firestore.doc(path);
          const ref = Object.freeze({ get: () => request(async () => snapshot(await raw.get())) });
          refs.set(ref, raw);
          return ref;
        },
        runTransaction: async (callback, options) => {
          check();
          this.#mutation = true;
          return request(() => clients.firestore.runTransaction(async (tx) => {
          const rawRef = (ref) => {
            check();
            if (!refs.has(ref)) throw new Error('EXECUTOR_INVALID_REFERENCE');
            return refs.get(ref);
          };
          await callback(Object.freeze({
            get: (ref) => request(async () => snapshot(await tx.get(rawRef(ref)))),
            create: (ref, value) => { tx.create(rawRef(ref), value); },
            set: (ref, value) => { tx.set(rawRef(ref), value); },
            delete: (ref) => { tx.delete(rawRef(ref)); },
          }));
          check(); // a detached callback may have outlived task completion
          }, options));
        },
      });
      const auth = Object.freeze(Object.fromEntries([
        'getUser', 'setCustomUserClaims', 'revokeRefreshTokens',
      ].map((method) => [method, async (...args) => {
        check();
        if (method !== 'getUser') this.#mutation = true;
        return request(() => clients.auth[method](...args), method === 'getUser');
      }])));
      result = await task({ db, auth });
    } catch (caught) {
      error = caught;
    }
    // Synchronous seal: no facade can start another request after this point.
    this.#state = 'sealed';
    const detached = this.#pending !== 0;
    if (detached) failures.push('EXECUTOR_OUTSTANDING_REQUESTS');
    const outcome = error?.outcome ?? result?.outcome;
    const preWriteRefusal = !this.#mutation && !this.#rejected
      && error instanceof StoreRefusal && error.outcome === undefined;
    if (preWriteRefusal) error.outcome = 'refused-before-write';
    const readOnly = !this.#mutation && !this.#rejected && result?.dryRun === true;
    const known = readOnly || preWriteRefusal || ['refused-before-write', 'committed-verified',
      'committed-eligibility-changed'].includes(outcome);
    const confirmedPreWrite = error instanceof StoreRefusal && error.outcome === 'refused-before-write';
    if (!known || (this.#rejected && !confirmedPreWrite)) failures.push('EXECUTOR_SETTLEMENT_UNCONFIRMED');
    // No timeout authorizes CLEAN. The caller/supervisor may stop waiting, but
    // death/disconnection must leave ACTIVE and never invoke clean elsewhere.
    for (const [name, operation] of [
      ['FIRESTORE_TERMINATE', clients && (() => clients.firestore.terminate())],
      ['APP_DELETE', clients && (() => clients.deleteApp())],
    ]) {
      if (!operation) continue;
      try { await operation(); }
      catch { failures.push(`${name}_FAILED`); }
    }
    if (!clients) failures.push('EXECUTOR_CLIENT_START_FAILED');
    if (this.#pending !== 0 && !detached) failures.push('EXECUTOR_OUTSTANDING_REQUESTS');
    if (!failures.length) {
      try { await this.#admission.clean(); }
      catch { failures.push('QUARANTINE_CLEAN_UNCONFIRMED'); }
    }
    try { await this.#admission.release(); }
    catch { failures.push('LOCK_RELEASE_UNCONFIRMED'); }
    this.#state = 'finished';
    // Keep the transaction result/error verbatim. Metadata is a separate value.
    return Object.freeze({ result, error, quarantine: failures.length ? 'ACTIVE_OR_UNCONFIRMED' : 'CLEAN',
      cleanupComplete: failures.length === 0, cleanupFailures: Object.freeze(failures) });
  }
}
