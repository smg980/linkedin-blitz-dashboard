#!/usr/bin/env node
// Step D operator CLI for the one private campaign document. See secure/STEP_D_CAMPAIGN_STORE.md.
//
//   node scripts/blitz-campaign-store.mjs inspect --target <emulator|production> --project <id>
//   node scripts/blitz-campaign-store.mjs write   --target ... --project ... --input <envelope.json> [--expect-current <digest|none>] [--backup <file>] [--receipt <file>] [--apply]
//   node scripts/blitz-campaign-store.mjs retract --target ... --project ... [--expect-current <digest>] [--backup <file>] [--receipt <file>] [--apply]
//
// Identity and approval come from the environment, never argv (shell history, ps):
//   BLITZ_STORE_UID, BLITZ_STORE_CONFIRM_UID, BLITZ_STORE_APPROVAL
// All arguments and variables are validated before the Admin SDK is loaded.
// Output is JSON with booleans and envelope digests only.
//
// Exit codes: 0 committed and verified (or a dry run); 1 refused, nothing was
// written; 3 STORE_OUTCOME_UNKNOWN, the write may have applied, read the
// receipt and inspect, never re-run the same apply; 4 committed but the owner
// record changed during the commit, read the receipt.
//
// F4: production uses only the operator's gcloud user ADC file (checked, then
// handed to the SDK explicitly) and requires it to belong to the account the
// gcloud CLI reports as active. F5: input, backup, receipt and lock paths must
// be outside the repository by path segment, real path and file identity.
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  assertNotPublicBundle,
  assertOperatorCredential,
  assertSameOperator,
  assertTarget,
  campaignPath,
  envelopeDigest,
  MAX_ENVELOPE_BYTES,
  parseEnvelopeText,
  runStoreAction,
  StoreRefusal,
} from '../secure/campaign-store.mjs';
import { acquireOperatorLock, lockDirectory, LockRefusal } from '../secure/operator-lock.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const VALUE_FLAGS = new Set(['--target', '--project', '--input', '--expect-current', '--backup', '--receipt']);

function need(condition, code) {
  if (!condition) throw new StoreRefusal(code);
}

export function parseArgs(argv) {
  const [action, ...rest] = argv;
  need(['inspect', 'write', 'retract'].includes(action), 'STORE_INVALID_ACTION');
  const opts = { action, apply: false };
  const seen = new Set();
  for (let i = 0; i < rest.length; i++) {
    const flag = rest[i];
    need(!seen.has(flag), 'STORE_DUPLICATE_ARGUMENT');
    seen.add(flag);
    if (flag === '--apply') {
      opts.apply = true;
      continue;
    }
    need(VALUE_FLAGS.has(flag), 'STORE_INVALID_ARGUMENTS');
    const value = rest[++i];
    need(typeof value === 'string' && value.length > 0 && !value.startsWith('--'), 'STORE_INVALID_ARGUMENTS');
    opts[flag.slice(2).replace(/-([a-z])/g, (_, c) => c.toUpperCase())] = value;
  }
  if (action !== 'write') need(!opts.input, 'STORE_INPUT_ONLY_FOR_WRITE');
  if (action === 'inspect') need(!opts.apply && !opts.backup && !opts.expectCurrent && !opts.receipt, 'STORE_INSPECT_IS_READ_ONLY');
  return opts;
}

// F5: outside means the first path segment is "..", not that the string starts
// with "..": "<repo>/..private/x" and "<repo>/..backup.json" are inside.
export function outsideRepository(absolute, code, root = ROOT) {
  const relative = path.relative(root, absolute);
  const outside = relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative);
  need(relative !== '' && outside, code);
  return absolute;
}

// The real repository root, compared by segment, and then by file identity up
// the whole ancestry, so a bind mount or a differently-cased path to the same
// directory is still inside. `absolute` must already be a resolved real path.
export async function assertOutsideRepository(absolute, code, root = ROOT) {
  const realRoot = await fs.realpath(root);
  outsideRepository(absolute, code, realRoot);
  const rootInfo = await fs.stat(realRoot);
  let dir = absolute;
  for (;;) {
    const info = await fs.stat(dir).catch(() => null);
    need(!(info && info.dev === rootInfo.dev && info.ino === rootInfo.ino), code);
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return absolute;
}

async function resolveInput(file) {
  let real;
  try {
    real = await fs.realpath(file);
  } catch {
    throw new StoreRefusal('STORE_INPUT_UNREADABLE');
  }
  await assertOutsideRepository(real, 'STORE_INPUT_INSIDE_REPOSITORY');
  const stat = await fs.stat(real);
  need(stat.isFile() && stat.size <= MAX_ENVELOPE_BYTES * 2, 'STORE_ENVELOPE_TOO_LARGE');
  const raw = await fs.readFile(real);
  const envelope = parseEnvelopeText(raw.toString('utf8'));
  // The committed GitHub Pages bundle is public; it must never be loaded as private data.
  let publicText = null;
  try {
    publicText = await fs.readFile(path.join(ROOT, 'docs', 'data.enc.json'), 'utf8');
  } catch {
    publicText = null;
  }
  if (publicText !== null) {
    let publicEnvelope;
    try {
      publicEnvelope = parseEnvelopeText(publicText);
    } catch {
      throw new StoreRefusal('STORE_PUBLIC_BUNDLE_UNREADABLE');
    }
    assertNotPublicBundle(envelope, publicEnvelope);
  }
  return { envelope, fileSha256: createHash('sha256').update(raw).digest('hex') };
}

// A new private file: its directory's real path, outside the repository, and
// no existing entry (file, directory or symlink) at the name.
async function resolveNewPrivateFile(file, prefix) {
  const absolute = path.resolve(file);
  const name = path.basename(absolute);
  need(name !== '' && name !== '.' && name !== '..', `${prefix}_INSIDE_REPOSITORY`);
  let dir;
  try {
    dir = await fs.realpath(path.dirname(absolute));
  } catch {
    throw new StoreRefusal(`${prefix}_DIRECTORY_MISSING`);
  }
  const target = path.join(dir, name);
  await assertOutsideRepository(target, `${prefix}_INSIDE_REPOSITORY`);
  const exists = await fs.lstat(target).then(() => true, () => false);
  need(!exists, `${prefix}_EXISTS`);
  return target;
}

function resolveBackup(file) {
  return resolveNewPrivateFile(file, 'STORE_BACKUP');
}

function resolveReceipt(file) {
  return resolveNewPrivateFile(file, 'STORE_RECEIPT');
}

async function syncDirectory(dir) {
  const handle = await fs.open(dir, 'r');
  try { await handle.sync(); } finally { await handle.close(); }
}

// F6: the receipt is created exclusively (mode 600) and flushed before any
// mutation; every update replaces it atomically and is flushed too.
export async function createReceiptFile(file, body) {
  const handle = await fs.open(file, 'wx', 0o600);
  try {
    await handle.writeFile(`${JSON.stringify(body, null, 2)}\n`);
    await handle.sync();
  } finally {
    await handle.close();
  }
  await syncDirectory(path.dirname(file));
}

export async function updateReceiptFile(file, body) {
  const temp = `${file}.${process.pid}.tmp`;
  const handle = await fs.open(temp, 'wx', 0o600);
  try {
    await handle.writeFile(`${JSON.stringify(body, null, 2)}\n`);
    await handle.sync();
  } finally {
    await handle.close();
  }
  await fs.rename(temp, file);
  await syncDirectory(path.dirname(file));
}

// Exclusive create, mode 600, then re-read: the digest proves what is on disk.
export async function writeBackupFile(file, envelope) {
  const handle = await fs.open(file, 'wx', 0o600);
  try {
    await handle.writeFile(`${JSON.stringify(envelope)}\n`);
    await handle.sync();
  } finally {
    await handle.close();
  }
  await syncDirectory(path.dirname(file));
  return envelopeDigest(parseEnvelopeText(await fs.readFile(file, 'utf8')));
}

// F4: the gcloud user ADC file, from gcloud's own configuration directory.
export function adcFilePath(env = process.env, home = os.homedir()) {
  if (env.CLOUDSDK_CONFIG) {
    need(path.isAbsolute(env.CLOUDSDK_CONFIG), 'STORE_ADC_CONFIG_DIR');
    return path.join(env.CLOUDSDK_CONFIG, 'application_default_credentials.json');
  }
  return path.join(home, '.config', 'gcloud', 'application_default_credentials.json');
}

export async function loadOperatorCredential({ env = process.env, projectId, home = os.homedir() } = {}) {
  const file = adcFilePath(env, home);
  let info;
  let text;
  try {
    info = await fs.lstat(file);
    text = await fs.readFile(file, 'utf8');
  } catch {
    throw new StoreRefusal('STORE_ADC_MISSING');
  }
  await assertOutsideRepository(await fs.realpath(file), 'STORE_ADC_INSIDE_REPOSITORY');
  return assertOperatorCredential({ text, info, operatorUid: typeof process.getuid === 'function' ? process.getuid() : null, projectId });
}

// Asks Google which account the ADC refresh token belongs to, and gcloud which
// account is active. Neither value leaves this function.
export async function bindOperatorIdentity({ credential, fetchImpl = fetch, gcloud = runGcloudAccount }) {
  let adcEmail;
  let adcEmailVerified;
  try {
    const { access_token: token } = await credential.getAccessToken();
    const response = await fetchImpl('https://oauth2.googleapis.com/tokeninfo', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ access_token: token }).toString(),
    });
    if (!response.ok) throw new Error('tokeninfo');
    const info = await response.json();
    adcEmail = info.email;
    adcEmailVerified = info.email_verified === true || info.email_verified === 'true';
  } catch {
    throw new StoreRefusal('STORE_ADC_IDENTITY_UNAVAILABLE');
  }
  return assertSameOperator({ adcEmail, adcEmailVerified, gcloudAccount: gcloud() });
}

function runGcloudAccount() {
  const env = { ...process.env };
  for (const key of Object.keys(env)) if (/PASSPHRASE|^BLITZ_STORE_/i.test(key)) delete env[key];
  const result = spawnSync('gcloud', ['config', 'get-value', 'account', '--quiet'], { encoding: 'utf8', timeout: 20000, env });
  return result.status === 0 ? String(result.stdout || '').trim() : '';
}

export async function main(argv = process.argv.slice(2), env = process.env, deps = {}) {
  const opts = parseArgs(argv);
  assertTarget({ target: opts.target, projectId: opts.project, env });
  const uid = env.BLITZ_STORE_UID;
  campaignPath(uid);
  if (opts.action === 'write') need(opts.input, 'STORE_INPUT_REQUIRED');
  const input = opts.action === 'write' ? await resolveInput(opts.input) : null;
  const backupPath = opts.backup && opts.apply ? await resolveBackup(opts.backup) : opts.backup;
  if (opts.apply) need(opts.receipt, 'STORE_RECEIPT_REQUIRED');
  const receiptPath = opts.apply ? await resolveReceipt(opts.receipt) : undefined;
  if (receiptPath && backupPath) need(receiptPath !== backupPath, 'STORE_RECEIPT_EXISTS');

  // Coordinated operator control: no claim tool or second store run may
  // overlap a mutation for this project.
  let lock = null;
  if (opts.apply) {
    const dir = lockDirectory(env);
    await fs.mkdir(dir, { recursive: true, mode: 0o700 }).catch(() => {});
    await assertOutsideRepository(await fs.realpath(dir).catch(() => path.resolve(dir)), 'STORE_LOCK_INSIDE_REPOSITORY');
    try {
      lock = await acquireOperatorLock({ project: opts.project, purpose: `store-${opts.action}`, dir });
    } catch (error) {
      throw new StoreRefusal(error instanceof LockRefusal && error.code === 'LOCK_HELD' ? 'STORE_OPERATOR_LOCK_HELD' : 'STORE_OPERATOR_LOCK_UNAVAILABLE');
    }
  }
  let app;
  let deleteApp;
  try {
    const admin = await import('firebase-admin/app');
    deleteApp = admin.deleteApp;
    const { getFirestore } = await import('firebase-admin/firestore');
    const { getAuth } = await import('firebase-admin/auth');
    let appOptions = { projectId: opts.project };
    if (opts.target === 'production') {
      // F4: one explicit, checked user credential. The SDK never searches for ADC.
      const adc = await (deps.loadOperatorCredential || loadOperatorCredential)({ env, projectId: opts.project });
      const credential = admin.refreshToken(adc);
      await (deps.bindOperatorIdentity || bindOperatorIdentity)({ credential });
      appOptions = { projectId: opts.project, credential };
    }
    app = admin.initializeApp(appOptions, `blitz-store-${process.pid}-${Date.now()}`);
    const result = await runStoreAction({
      db: getFirestore(app),
      auth: getAuth(app),
      backup: { write: writeBackupFile },
      receipt: { create: createReceiptFile, update: updateReceiptFile },
      target: opts.target,
      projectId: opts.project,
      action: opts.action,
      uid,
      confirmUid: env.BLITZ_STORE_CONFIRM_UID,
      approval: env.BLITZ_STORE_APPROVAL,
      input: input?.envelope ?? null,
      expectCurrent: opts.expectCurrent,
      backupPath,
      receiptPath,
      apply: opts.apply,
    });
    return {
      target: opts.target,
      ...result,
      ...(opts.target === 'production' ? { operatorIdentityBound: true } : {}),
      ...(input ? { inputFileSha256: input.fileSha256 } : {}),
    };
  } catch (error) {
    // SDK errors can carry uids, emails or response bodies. Only fixed codes leave.
    if (error instanceof StoreRefusal) throw error;
    throw new StoreRefusal('STORE_OPERATION_FAILED');
  } finally {
    if (app) await Promise.race([deleteApp(app), new Promise((resolve) => setTimeout(resolve, 3000))]);
    if (lock) await lock.release();
  }
}

export function exitCodeFor(error) {
  if (error?.outcome === 'unknown') return 3;
  if (error?.outcome === 'committed-eligibility-changed') return 4;
  return 1;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().then((result) => {
    console.log(JSON.stringify(result));
    process.exit(0);
  }).catch((error) => {
    const code = error instanceof StoreRefusal ? error.code : 'STORE_OPERATION_FAILED';
    console.error(`STORE_REFUSED ${code}`);
    process.exit(error instanceof StoreRefusal ? exitCodeFor(error) : 1);
  });
}
