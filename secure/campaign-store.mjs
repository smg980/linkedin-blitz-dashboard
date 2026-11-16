// Step D: governed write and retract of the one private campaign document,
// blitzOwners/{uid}/campaign/current, through the Firebase Admin SDK.
//
// The tool handles ciphertext only. The envelope is built beforehand with the
// existing scripts/build.mjs (BLITZ_OUTPUT_DIR outside this repository) and the
// owner's passphrase; this module never sees a passphrase or plaintext.
//
// Every mutation is a dry run unless --apply is given, and --apply needs:
//   - the exact uid twice (BLITZ_STORE_UID and BLITZ_STORE_CONFIRM_UID),
//   - an approval string bound to the action and envelope digest
//     (WRITE:<input digest> or RETRACT:<current digest>),
//   - the digest the operator expects to be live now (--expect-current, or "none"),
//     re-checked inside a Firestore transaction,
//   - a backup file of the current ciphertext whenever a document already exists,
//   - a private recovery receipt (F6), persisted before any mutation.
// Output carries booleans and envelope digests only: never a uid, email or claim.
//
// Outcomes (F6). Every apply ends in exactly one of:
//   refused-before-write           nothing was committed (CAS mismatch, owner
//                                   changed, backup or receipt failure, read error
//                                   before the write was staged)
//   committed-verified             the commit was acknowledged and read back
//   unknown                        the commit may or may not have applied (lost
//                                   acknowledgement, failed or mismatched readback)
//   committed-eligibility-changed  committed and read back, but the owner record
//                                   changed during the commit (claim race)
// The transaction runs with maxAttempts 1 (no transaction re-run) and the
// Firestore client is built with Commit retries disabled at the GAPIC and gRPC
// layers (R5, secure/operator-clients.mjs), so an ambiguous commit is sent once
// and never repeated by the SDK or by this tool. The receipt records what to do
// either way.
import { createHash } from 'node:crypto';
import { isEnvelope } from './envelope.mjs';

export const PRODUCTION_PROJECT = 'master-intelligence-5496f';
export const ENVELOPE_KEYS = Object.freeze(['v', 'alg', 'kdf', 'iterations', 'salt', 'iv', 'ct']);
// Firestore's document limit is 1 MiB including field names; keep clear of it.
export const MAX_ENVELOPE_BYTES = 1_000_000;
const UID = /^[A-Za-z0-9_-]{1,128}$/;
const DIGEST = /^[0-9a-f]{64}$/;
const LOOPBACK_HOST = /^(127\.0\.0\.1|localhost):\d{1,5}$/;
// F4: google-auth-library reads GOOGLE_APPLICATION_CREDENTIALS *and*
// google_application_credentials; gcloud honours its own overrides. Any
// spelling, present at all (even empty), is refused.
const CREDENTIAL_ENV = /^(GOOGLE_APPLICATION_CREDENTIALS|FIREBASE_TOKEN|GOOGLE_OAUTH_ACCESS_TOKEN|CLOUDSDK_AUTH_ACCESS_TOKEN|CLOUDSDK_AUTH_ACCESS_TOKEN_FILE|CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE|GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES)$/i;

export function isCredentialEnvKey(key) {
  return CREDENTIAL_ENV.test(key);
}

export function credentialEnvPresent(env = {}) {
  return Object.keys(env).some(isCredentialEnvKey);
}

export class StoreRefusal extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

function need(condition, code) {
  if (!condition) throw new StoreRefusal(code);
}

export function campaignPath(uid) {
  need(typeof uid === 'string' && UID.test(uid), 'STORE_INVALID_UID');
  return `blitzOwners/${uid}/campaign/current`;
}

export function canonicalEnvelope(value) {
  need(value && typeof value === 'object' && !Array.isArray(value), 'STORE_NOT_AN_ENVELOPE');
  need(Object.keys(value).sort().join(',') === [...ENVELOPE_KEYS].sort().join(','), 'STORE_ENVELOPE_FIELDS');
  const ordered = Object.fromEntries(ENVELOPE_KEYS.map((key) => [key, value[key]]));
  need(isEnvelope(ordered), 'STORE_NOT_AN_ENVELOPE');
  // atob() tolerates whitespace; the stored strings must be strict base64.
  for (const key of ['salt', 'iv', 'ct']) {
    need(/^[A-Za-z0-9+/]+={0,2}$/.test(ordered[key]) && ordered[key].length % 4 === 0, 'STORE_NOT_AN_ENVELOPE');
  }
  need(Buffer.byteLength(JSON.stringify(ordered), 'utf8') <= MAX_ENVELOPE_BYTES, 'STORE_ENVELOPE_TOO_LARGE');
  return ordered;
}

export function envelopeDigest(value) {
  return createHash('sha256').update(JSON.stringify(canonicalEnvelope(value)), 'utf8').digest('hex');
}

export function parseEnvelopeText(text) {
  need(typeof text === 'string' && text.length <= MAX_ENVELOPE_BYTES * 2, 'STORE_ENVELOPE_TOO_LARGE');
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    throw new StoreRefusal('STORE_NOT_JSON');
  }
  return canonicalEnvelope(value);
}

// The public GitHub Pages bundle is not private data. Refuse to load it, or
// anything sharing its salt, IV or ciphertext, into the owner-only document.
export function assertNotPublicBundle(envelope, publicEnvelope) {
  if (!publicEnvelope) return;
  need(envelope.salt !== publicEnvelope.salt && envelope.iv !== publicEnvelope.iv && envelope.ct !== publicEnvelope.ct,
    'STORE_PUBLIC_BUNDLE_REFUSED');
}

export function assertTarget({ target, projectId, env = {} }) {
  need(!env.DASHBOARD_PASSPHRASE, 'STORE_PASSPHRASE_IN_ENV');
  if (target === 'emulator') {
    need(typeof projectId === 'string' && /^demo-[a-z0-9-]{1,40}$/.test(projectId) && !projectId.includes(PRODUCTION_PROJECT),
      'STORE_EMULATOR_PROJECT');
    need(LOOPBACK_HOST.test(env.FIRESTORE_EMULATOR_HOST || ''), 'STORE_LOOPBACK_FIRESTORE_REQUIRED');
    need(LOOPBACK_HOST.test(env.FIREBASE_AUTH_EMULATOR_HOST || ''), 'STORE_LOOPBACK_AUTH_REQUIRED');
    need(!credentialEnvPresent(env), 'STORE_CREDENTIAL_ENV_REFUSED');
    return { target, projectId };
  }
  if (target === 'production') {
    need(projectId === PRODUCTION_PROJECT, 'STORE_PRODUCTION_PROJECT');
    need(!env.CI && !env.GITHUB_ACTIONS, 'STORE_NEVER_FROM_CI');
    need(!env.FIRESTORE_EMULATOR_HOST && !env.FIREBASE_AUTH_EMULATOR_HOST, 'STORE_EMULATOR_ENV_WITH_PRODUCTION');
    // Never a key file, an access-token override or a CI token. The credential is
    // the operator's own user ADC file, checked by assertOperatorCredential and
    // bound to the active gcloud account; generic ADC is never consulted.
    need(!credentialEnvPresent(env), 'STORE_KEY_FILE_REFUSED');
    need(!Object.keys(env).some((key) => /PASSPHRASE/i.test(key) && env[key]), 'STORE_PASSPHRASE_IN_ENV');
    return { target, projectId };
  }
  throw new StoreRefusal('STORE_INVALID_TARGET');
}

// F4: the one production credential Step D accepts is the gcloud user ADC file
// written by `gcloud auth application-default login` in the operator's session
// (type authorized_user). Service-account keys, impersonation, external
// accounts and the metadata server are all refused. The returned object is
// handed to the Admin SDK directly, so the SDK never searches for credentials.
const ADC_FIELDS = new Set(['type', 'client_id', 'client_secret', 'refresh_token', 'quota_project_id', 'universe_domain', 'account']);

export function assertOperatorCredential({ text, info, operatorUid, projectId }) {
  need(info && info.isFile() && !info.isSymbolicLink(), 'STORE_ADC_NOT_REGULAR_FILE');
  need(operatorUid == null || info.uid === operatorUid, 'STORE_ADC_NOT_OWNED_BY_OPERATOR');
  need((info.mode & 0o022) === 0, 'STORE_ADC_WRITABLE_BY_OTHERS');
  let cred;
  try {
    cred = JSON.parse(text);
  } catch {
    throw new StoreRefusal('STORE_ADC_UNREADABLE');
  }
  need(cred && typeof cred === 'object' && !Array.isArray(cred), 'STORE_ADC_UNREADABLE');
  need(cred.type === 'authorized_user', 'STORE_ADC_NOT_USER_CREDENTIAL');
  need(Object.keys(cred).every((key) => ADC_FIELDS.has(key)), 'STORE_ADC_UNEXPECTED_FIELDS');
  for (const key of ['client_id', 'client_secret', 'refresh_token']) {
    need(typeof cred[key] === 'string' && cred[key].length > 0, 'STORE_ADC_UNREADABLE');
  }
  need(cred.quota_project_id === projectId, 'STORE_ADC_QUOTA_PROJECT');
  need(cred.universe_domain == null || cred.universe_domain === 'googleapis.com', 'STORE_ADC_UNIVERSE');
  return cred;
}

// Binds that credential to the account the gcloud CLI says is active. Neither
// identity is returned or printed; only whether they are the same account.
export function assertSameOperator({ adcEmail, adcEmailVerified, gcloudAccount }) {
  need(typeof adcEmail === 'string' && adcEmail.includes('@') && adcEmailVerified === true, 'STORE_ADC_IDENTITY_UNAVAILABLE');
  need(typeof gcloudAccount === 'string' && gcloudAccount.includes('@'), 'STORE_GCLOUD_ACCOUNT_UNAVAILABLE');
  need(adcEmail.trim().toLowerCase() === gcloudAccount.trim().toLowerCase(), 'STORE_ADC_IDENTITY_MISMATCH');
  return true;
}

// Everything about the Auth record that decides whether a write is allowed,
// reduced to one digest. Never printed.
export function eligibilityFingerprint(user) {
  const sortDeep = (value) => (Array.isArray(value)
    ? value.map(sortDeep)
    : value && typeof value === 'object'
      ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, sortDeep(value[key])]))
      : value);
  return createHash('sha256').update(JSON.stringify(sortDeep({
    uid: user?.uid ?? null,
    disabled: user?.disabled ?? null,
    emailVerified: user?.emailVerified ?? null,
    providers: Array.isArray(user?.providerData) ? user.providerData.map((p) => p?.providerId ?? null).sort() : null,
    customClaims: user?.customClaims ?? null,
    tokensValidAfterTime: user?.tokensValidAfterTime ?? null,
  })), 'utf8').digest('hex');
}

export function ownerEligibility(user, uid) {
  const checks = {
    exists: user?.uid === uid,
    enabled: user?.disabled === false,
    emailVerified: user?.emailVerified === true,
    google: Array.isArray(user?.providerData) && user.providerData.some((p) => p?.providerId === 'google.com'),
    owner: user?.customClaims?.blitzOwner === true,
  };
  return { ...checks, eligible: Object.values(checks).every(Boolean) };
}

export function planStoreAction({ target, action, uid, confirmUid, approval, user, current, input, expectCurrent, backupPath, receiptPath, apply = false }) {
  need(['inspect', 'write', 'retract'].includes(action), 'STORE_INVALID_ACTION');
  need(typeof apply === 'boolean', 'STORE_INVALID_APPLY');
  campaignPath(uid);
  const eligibility = ownerEligibility(user, uid);
  need(eligibility.exists, 'STORE_UNKNOWN_UID');
  // A local emulator accidentally loaded with real identities is still refused.
  if (target === 'emulator') need(/^[^@\s]+@example\.com$/.test(user.email || ''), 'STORE_SYNTHETIC_ACCOUNT_REQUIRED');
  const currentDigest = current ? envelopeDigest(current) : null;
  const requiredExpectCurrent = currentDigest || 'none';
  const plan = {
    action,
    ownerEligible: eligibility.eligible,
    documentExists: Boolean(current),
    currentDigest,
    requiredExpectCurrent,
  };
  if (action === 'inspect') {
    need(!apply, 'STORE_INSPECT_IS_READ_ONLY');
    return plan;
  }
  if (action === 'write') {
    need(input, 'STORE_INPUT_REQUIRED');
    plan.inputDigest = envelopeDigest(input);
    need(plan.inputDigest !== currentDigest, 'STORE_ALREADY_CURRENT');
    plan.requiredApproval = `WRITE:${plan.inputDigest}`;
  } else {
    need(current, 'STORE_NOTHING_TO_RETRACT');
    plan.requiredApproval = `RETRACT:${currentDigest}`;
  }
  if (!apply) return plan;
  need(expectCurrent === 'none' || DIGEST.test(expectCurrent || ''), 'STORE_EXPECT_CURRENT_REQUIRED');
  need(expectCurrent === requiredExpectCurrent, 'STORE_CURRENT_MISMATCH');
  need(confirmUid === uid, 'STORE_EXACT_UID_CONFIRMATION_REQUIRED');
  need(approval === plan.requiredApproval, 'STORE_APPROVAL_REQUIRED');
  // Retract stays possible for a revoked or disabled owner; writing needs a live owner.
  if (action === 'write') need(eligibility.eligible, 'STORE_OWNER_NOT_ELIGIBLE');
  if (current) need(typeof backupPath === 'string' && backupPath.length > 0, 'STORE_BACKUP_REQUIRED');
  need(typeof receiptPath === 'string' && receiptPath.length > 0, 'STORE_RECEIPT_REQUIRED');
  return plan;
}

function currentFrom(snapshot) {
  if (!snapshot?.exists) return null;
  try {
    return canonicalEnvelope(snapshot.data());
  } catch {
    // Something other than our envelope is stored there. Stop for a human.
    throw new StoreRefusal('STORE_CURRENT_NOT_ENVELOPE');
  }
}

function refusal(code, outcome) {
  const error = new StoreRefusal(code);
  error.outcome = outcome;
  return error;
}

// What undoes this mutation if it committed. A first write is undone by a
// retract (which needs its own backup); a replacement or a retract by writing
// the backup back, with the CAS value the undo will need.
export function rollbackIfCommitted({ action, plan, backupPath }) {
  const after = action === 'write' ? plan.inputDigest : 'none';
  if (!plan.currentDigest) {
    return { action: 'retract', expectCurrent: after, approval: `RETRACT:${after}`, backupRequired: true };
  }
  return {
    action: 'write',
    input: backupPath,
    inputDigest: plan.currentDigest,
    expectCurrent: after,
    approval: `WRITE:${plan.currentDigest}`,
    backupRequired: after !== 'none',
  };
}

// db: { doc(path) -> ref{ get() }, runTransaction(fn(tx{ get, create, set, delete }), { maxAttempts }) }
// auth: { getUser(uid) }
// backup: { write(path, envelope) -> digest of what was written and re-read }
// receipt: { create(path, body) exclusive + durable, update(path, body) atomic + durable }
export async function runStoreAction({ db, auth, backup, receipt, target, projectId, action, uid, confirmUid, approval, input, expectCurrent, backupPath, receiptPath, apply = false, now = () => new Date().toISOString() }) {
  const path = campaignPath(uid);
  const readUser = async () => {
    try {
      return await auth.getUser(uid);
    } catch {
      throw new StoreRefusal('STORE_UNKNOWN_UID');
    }
  };
  const user = await readUser();
  const ref = db.doc(path);
  const current = currentFrom(await ref.get());
  const plan = planStoreAction({ target, action, uid, confirmUid, approval, user, current, input, expectCurrent, backupPath, receiptPath, apply });
  if (!apply) return { dryRun: true, ...plan };
  need(receipt && typeof receipt.create === 'function' && typeof receipt.update === 'function', 'STORE_RECEIPT_REQUIRED');

  const planned = eligibilityFingerprint(user);
  const intended = action === 'write' ? plan.inputDigest : 'none';
  const record = {
    version: 1,
    tool: 'blitz-campaign-store',
    target,
    projectId: projectId ?? null,
    action,
    uidSha256: createHash('sha256').update(uid, 'utf8').digest('hex'),
    createdAt: now(),
    updatedAt: null,
    status: 'PREPARED',
    refusal: null,
    expectCurrent,
    previousDigest: plan.currentDigest,
    intendedDigest: intended,
    backup: { required: Boolean(current), path: current ? backupPath : null, digest: null, verified: false },
    observedDigest: null,
    rollbackIfCommitted: rollbackIfCommitted({ action, plan, backupPath }),
    ifNotCommitted: 'Nothing to undo. Run inspect; never repeat an apply without a fresh dry run.',
  };
  const save = async (patch, { first = false } = {}) => {
    Object.assign(record, patch, { updatedAt: now() });
    if (first) await receipt.create(receiptPath, structuredClone(record));
    else await receipt.update(receiptPath, structuredClone(record));
  };
  // Records a refusal before any write. The receipt update is best effort: the
  // refusal stands either way and nothing was mutated.
  const refuseBeforeWrite = async (code) => {
    try { await save({ status: 'REFUSED_PRE_WRITE', refusal: code }); } catch { /* still refused */ }
    return refusal(code, 'refused-before-write');
  };
  const observe = async () => {
    try {
      const seen = currentFrom(await ref.get());
      return seen ? envelopeDigest(seen) : 'none';
    } catch {
      return 'unreadable';
    }
  };

  try {
    await save({}, { first: true });
  } catch {
    throw refusal('STORE_RECEIPT_FAILED', 'refused-before-write');
  }
  if (current) {
    let backupDigest;
    try {
      backupDigest = await backup.write(backupPath, current);
    } catch {
      throw await refuseBeforeWrite('STORE_BACKUP_FAILED');
    }
    if (backupDigest !== plan.currentDigest) throw await refuseBeforeWrite('STORE_BACKUP_VERIFICATION_FAILED');
    record.backup = { ...record.backup, digest: backupDigest, verified: true };
  }
  // Claim race: the owner record must be unchanged and eligible right before
  // the commit. Firestore cannot lock Auth, so this re-check, the one inside
  // the transaction and the one after it narrow the window; the operator lock
  // (secure/operator-lock.mjs) keeps claim tools and this tool from overlapping.
  const unchangedOwner = async () => {
    const latest = await readUser();
    return ownerEligibility(latest, uid).eligible && eligibilityFingerprint(latest) === planned;
  };
  if (action === 'write' && !(await unchangedOwner().catch(() => false))) {
    throw await refuseBeforeWrite('STORE_OWNER_CHANGED_BEFORE_COMMIT');
  }
  try {
    await save({ status: 'READY_TO_COMMIT' });
  } catch {
    throw refusal('STORE_RECEIPT_FAILED', 'refused-before-write');
  }

  let staged = false;
  let callbackDone = false;
  let callbackRefusal = null;
  try {
    await db.runTransaction(async (tx) => {
      let latest;
      try {
        latest = currentFrom(await tx.get(ref));
      } catch (error) {
        callbackRefusal = error instanceof StoreRefusal ? error.code : 'STORE_PRE_WRITE_READ_FAILED';
        throw error;
      }
      if ((latest ? envelopeDigest(latest) : 'none') !== expectCurrent) {
        callbackRefusal = 'STORE_CONCURRENT_CHANGE';
        throw new StoreRefusal(callbackRefusal);
      }
      if (action === 'write' && !(await unchangedOwner().catch(() => false))) {
        callbackRefusal = 'STORE_OWNER_CHANGED_BEFORE_COMMIT';
        throw new StoreRefusal(callbackRefusal);
      }
      staged = true;
      if (action === 'retract') tx.delete(ref);
      else if (latest) tx.set(ref, input);
      else tx.create(ref, input);
      callbackDone = true;
    }, { maxAttempts: 1 });
  } catch {
    if (!staged || !callbackDone) {
      // The callback stopped before returning: the SDK never sent a commit.
      throw await refuseBeforeWrite(callbackRefusal || 'STORE_PRE_WRITE_FAILED');
    }
    // The commit was sent and its result is not known. Record, never retry.
    const observedDigest = await observe();
    try { await save({ status: 'OUTCOME_UNKNOWN', observedDigest }); } catch { /* reported below */ }
    throw refusal('STORE_OUTCOME_UNKNOWN', 'unknown');
  }

  let afterDigest;
  try {
    const after = currentFrom(await ref.get());
    afterDigest = after ? envelopeDigest(after) : 'none';
  } catch {
    afterDigest = 'unreadable';
  }
  if (afterDigest !== intended) {
    try { await save({ status: 'OUTCOME_UNKNOWN', observedDigest: afterDigest }); } catch { /* reported below */ }
    throw refusal('STORE_OUTCOME_UNKNOWN', 'unknown');
  }
  if (action === 'write' && !(await unchangedOwner().catch(() => false))) {
    try { await save({ status: 'COMMITTED_ELIGIBILITY_CHANGED', observedDigest: afterDigest }); } catch { /* reported below */ }
    throw refusal('STORE_ELIGIBILITY_CHANGED_DURING_COMMIT', 'committed-eligibility-changed');
  }
  try {
    await save({ status: 'COMMITTED_VERIFIED', observedDigest: afterDigest });
  } catch {
    // Committed and verified, but the receipt could not record it: say so.
    throw refusal('STORE_RECEIPT_FAILED_AFTER_COMMIT', 'committed-verified');
  }
  const liveDigest = afterDigest === 'none' ? null : afterDigest;
  return {
    dryRun: false,
    verified: true,
    outcome: 'committed-verified',
    action,
    previousDigest: plan.currentDigest,
    liveDigest,
    backupWritten: record.backup.verified,
    receiptWritten: true,
    rollback: record.rollbackIfCommitted,
  };
}
