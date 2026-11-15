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
//   - a backup file of the current ciphertext whenever a document already exists.
// Output carries booleans and envelope digests only: never a uid, email or claim.
import { createHash } from 'node:crypto';
import { isEnvelope } from './envelope.mjs';

export const PRODUCTION_PROJECT = 'master-intelligence-5496f';
export const ENVELOPE_KEYS = Object.freeze(['v', 'alg', 'kdf', 'iterations', 'salt', 'iv', 'ct']);
// Firestore's document limit is 1 MiB including field names; keep clear of it.
export const MAX_ENVELOPE_BYTES = 1_000_000;
const UID = /^[A-Za-z0-9_-]{1,128}$/;
const DIGEST = /^[0-9a-f]{64}$/;
const LOOPBACK_HOST = /^(127\.0\.0\.1|localhost):\d{1,5}$/;

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
    need(!env.GOOGLE_APPLICATION_CREDENTIALS && !env.FIREBASE_TOKEN, 'STORE_CREDENTIAL_ENV_REFUSED');
    return { target, projectId };
  }
  if (target === 'production') {
    need(projectId === PRODUCTION_PROJECT, 'STORE_PRODUCTION_PROJECT');
    need(!env.CI && !env.GITHUB_ACTIONS, 'STORE_NEVER_FROM_CI');
    need(!env.FIRESTORE_EMULATOR_HOST && !env.FIREBASE_AUTH_EMULATOR_HOST, 'STORE_EMULATOR_ENV_WITH_PRODUCTION');
    // Use the operator's existing authorized gcloud session (ADC), never a key file or CI token.
    need(!env.GOOGLE_APPLICATION_CREDENTIALS && !env.FIREBASE_TOKEN, 'STORE_KEY_FILE_REFUSED');
    need(!Object.keys(env).some((key) => /PASSPHRASE/i.test(key) && env[key]), 'STORE_PASSPHRASE_IN_ENV');
    return { target, projectId };
  }
  throw new StoreRefusal('STORE_INVALID_TARGET');
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

export function planStoreAction({ target, action, uid, confirmUid, approval, user, current, input, expectCurrent, backupPath, apply = false }) {
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

// db: { doc(path) -> ref{ get() }, runTransaction(fn(tx{ get, create, set, delete })) }
// auth: { getUser(uid) }
// backup: { write(path, envelope) -> digest of what was written and re-read }
export async function runStoreAction({ db, auth, backup, target, action, uid, confirmUid, approval, input, expectCurrent, backupPath, apply = false }) {
  const path = campaignPath(uid);
  let user;
  try {
    user = await auth.getUser(uid);
  } catch {
    throw new StoreRefusal('STORE_UNKNOWN_UID');
  }
  const ref = db.doc(path);
  const current = currentFrom(await ref.get());
  const plan = planStoreAction({ target, action, uid, confirmUid, approval, user, current, input, expectCurrent, backupPath, apply });
  if (!apply) return { dryRun: true, ...plan };

  let backupDigest = null;
  if (current) {
    backupDigest = await backup.write(backupPath, current);
    need(backupDigest === plan.currentDigest, 'STORE_BACKUP_VERIFICATION_FAILED');
  }
  await db.runTransaction(async (tx) => {
    const latest = currentFrom(await tx.get(ref));
    need((latest ? envelopeDigest(latest) : 'none') === expectCurrent, 'STORE_CONCURRENT_CHANGE');
    if (action === 'retract') tx.delete(ref);
    else if (latest) tx.set(ref, input);
    else tx.create(ref, input);
  });
  const after = currentFrom(await ref.get());
  if (action === 'write') {
    need(after && envelopeDigest(after) === plan.inputDigest, 'STORE_READBACK_FAILED');
  } else {
    need(after === null, 'STORE_READBACK_FAILED');
  }
  const liveDigest = after ? plan.inputDigest : null;
  return {
    dryRun: false,
    verified: true,
    action,
    previousDigest: plan.currentDigest,
    liveDigest,
    backupWritten: backupDigest !== null,
    // Exactly how to undo this, with the CAS value it will need.
    rollback: plan.currentDigest
      ? { action: 'write', input: 'the backup file', expectCurrent: liveDigest || 'none', approval: `WRITE:${plan.currentDigest}` }
      : { action: 'retract', expectCurrent: liveDigest, approval: `RETRACT:${liveDigest}` },
  };
}
