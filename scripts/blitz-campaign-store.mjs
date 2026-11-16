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
// Exit codes: 0 committed and verified (or a dry run); 1 STORE_REFUSED, nothing
// was written; 3 STORE_UNRESOLVED STORE_OUTCOME_UNKNOWN, the write may have
// applied, read the receipt and inspect, never re-run the same apply; 4 committed
// but the owner record changed during the commit; 5 committed and verified but
// the receipt could not record it. Read the receipt for 3-5.
// R4: 10 + any of those (10, 11, 13, 14, 15) is the same outcome with cleanup
// incomplete: the operator lock may still be held (or its release could not be
// confirmed). The outcome is unchanged; never re-run the apply because of it.
//
// F4: production uses only the operator's gcloud user ADC file (checked, then
// handed to the SDK explicitly) and requires it to belong to the account the
// gcloud CLI reports as active. F5: input, backup, receipt and lock paths must
// be outside the repository by path segment, real path and file identity.
import { spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
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
  // R6: the directory must be the operator's own and closed to everyone else.
  need(privateDirectoryInfo(await fs.lstat(dir)), `${prefix}_DIRECTORY_NOT_PRIVATE`);
  const exists = await fs.lstat(target).then(() => true, () => false);
  need(!exists, `${prefix}_EXISTS`);
  return target;
}

function privateDirectoryInfo(info) {
  if (!info.isDirectory() || info.isSymbolicLink()) return false;
  if (typeof process.getuid === 'function' && info.uid !== process.getuid()) return false;
  return (info.mode & 0o077) === 0;
}

const sameFile = (a, b) => a.dev === b.dev && a.ino === b.ino;

// R6: the backup/receipt directory was checked (real path outside the
// repository, private) when the run started, but files are created later. If
// the directory, or an ancestor, is swapped for a symlink in between, a
// path-based open follows it. Node has no openat(2), so the file is created
// empty with O_EXCL|O_NOFOLLOW and then proven, through its descriptor, to be
// the only link to a new regular file inside the same, unchanged, still-private
// directory at the same real path. Only then is anything written, and only
// through that descriptor. Uses lstat/fstat/realpath only: macOS and Linux.
// If the check fails, an empty file may remain wherever the swapped path
// pointed; nothing else is written and the operation refuses.
export class PrivatePathChanged extends Error {
  constructor() {
    super('PRIVATE_PATH_CHANGED');
    this.code = 'PRIVATE_PATH_CHANGED';
  }
}

export async function openNewPrivateFile(file, { read = false } = {}) {
  const dir = path.dirname(file);
  const before = await fs.lstat(dir);
  if (!privateDirectoryInfo(before) || (await fs.realpath(dir)) !== dir) throw new PrivatePathChanged();
  const { O_CREAT, O_EXCL, O_NOFOLLOW, O_WRONLY, O_RDWR } = fsConstants;
  const handle = await fs.open(file, (read ? O_RDWR : O_WRONLY) | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600);
  try {
    const opened = await handle.stat();
    const after = await fs.lstat(dir);
    const atPath = await fs.lstat(file);
    const ok = opened.isFile() && opened.nlink === 1 && opened.size === 0
      && privateDirectoryInfo(after) && sameFile(after, before)
      && (await fs.realpath(dir)) === dir
      && atPath.isFile() && sameFile(atPath, opened);
    if (!ok) throw new PrivatePathChanged();
    return handle;
  } catch (error) {
    await handle.close().catch(() => {});
    throw error instanceof PrivatePathChanged ? error : new PrivatePathChanged();
  }
}

// After an atomic rename into the checked directory: the name must now be the
// file we wrote, in the same unchanged directory.
async function assertRenamedInPlace(file, written, dirBefore) {
  const dir = path.dirname(file);
  const after = await fs.lstat(dir);
  const atPath = await fs.lstat(file);
  if (!(privateDirectoryInfo(after) && sameFile(after, dirBefore) && (await fs.realpath(dir)) === dir
    && atPath.isFile() && sameFile(atPath, written) && atPath.nlink === 1)) throw new PrivatePathChanged();
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
// R6: every file is created through openNewPrivateFile and written only
// through the verified descriptor.
async function writeVerified(handle, text) {
  const data = Buffer.from(text, 'utf8');
  let offset = 0;
  while (offset < data.length) {
    const { bytesWritten } = await handle.write(data, offset, data.length - offset, offset);
    offset += bytesWritten;
  }
  await handle.sync();
}

export async function createReceiptFile(file, body) {
  const handle = await openNewPrivateFile(file);
  try {
    await writeVerified(handle, `${JSON.stringify(body, null, 2)}\n`);
  } finally {
    await handle.close();
  }
  await syncDirectory(path.dirname(file));
}

export async function updateReceiptFile(file, body) {
  const dirBefore = await fs.lstat(path.dirname(file));
  const temp = `${file}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`;
  const handle = await openNewPrivateFile(temp);
  let written;
  try {
    await writeVerified(handle, `${JSON.stringify(body, null, 2)}\n`);
    written = await handle.stat();
  } finally {
    await handle.close();
  }
  if (!sameFile(await fs.lstat(path.dirname(temp)), dirBefore)) throw new PrivatePathChanged();
  await fs.rename(temp, file);
  await assertRenamedInPlace(file, written, dirBefore);
  await syncDirectory(path.dirname(file));
}

// Exclusive create, mode 600, then re-read through the same descriptor: the
// digest proves what is on disk at the verified location.
export async function writeBackupFile(file, envelope) {
  const handle = await openNewPrivateFile(file, { read: true });
  let text;
  try {
    await writeVerified(handle, `${JSON.stringify(envelope)}\n`);
    const { size } = await handle.stat();
    const buffer = Buffer.alloc(size);
    let offset = 0;
    while (offset < size) {
      const { bytesRead } = await handle.read(buffer, offset, size - offset, offset);
      if (bytesRead === 0) break;
      offset += bytesRead;
    }
    text = buffer.subarray(0, offset).toString('utf8');
  } finally {
    await handle.close();
  }
  await syncDirectory(path.dirname(file));
  return envelopeDigest(parseEnvelopeText(text));
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
    try {
      lock = await (deps.acquireOperatorLock || acquireOperatorLock)({ project: opts.project, purpose: `store-${opts.action}`, dir });
    } catch (error) {
      const code = error instanceof LockRefusal ? error.code : '';
      if (code === 'LOCK_HELD') throw new StoreRefusal('STORE_OPERATOR_LOCK_HELD');
      if (code === 'LOCK_DIRECTORY_INSIDE_REPOSITORY') throw new StoreRefusal('STORE_LOCK_INSIDE_REPOSITORY');
      throw new StoreRefusal('STORE_OPERATOR_LOCK_UNAVAILABLE');
    }
    // The lock file itself must also sit outside the repository by file identity.
    try {
      await assertOutsideRepository(path.dirname(lock.file), 'STORE_LOCK_INSIDE_REPOSITORY');
    } catch (error) {
      const failures = await runCleanupSteps([['LOCK_RELEASE', () => lock.release()]]);
      const refusal = error instanceof StoreRefusal ? error : new StoreRefusal('STORE_LOCK_INSIDE_REPOSITORY');
      if (failures.length) Object.assign(refusal, { cleanupComplete: false, cleanupFailures: failures });
      throw refusal;
    }
  }
  let app;
  let deleteApp;
  let firestore;
  let outcome;
  try {
    const admin = await import('firebase-admin/app');
    deleteApp = admin.deleteApp;
    const { getAuth } = await import('firebase-admin/auth');
    const { createEmulatorFirestore, createOperatorClients } = await import('../secure/operator-clients.mjs');
    let appOptions = { projectId: opts.project };
    if (opts.target === 'production') {
      // F4: one explicit, checked user credential. The SDK never searches for ADC.
      // R3: built as a refresh client both pinned SDKs accept (see operator-clients.mjs).
      const adc = await (deps.loadOperatorCredential || loadOperatorCredential)({ env, projectId: opts.project });
      const clients = createOperatorClients({ adc, projectId: opts.project, testTransport: deps.testTransport });
      firestore = clients.firestore;
      await (deps.bindOperatorIdentity || bindOperatorIdentity)({ credential: clients.credential });
      appOptions = { projectId: opts.project, credential: clients.credential };
      if (deps.testTransport?.httpAgent) appOptions.httpAgent = deps.testTransport.httpAgent;
    } else {
      firestore = createEmulatorFirestore({ projectId: opts.project });
    }
    app = admin.initializeApp(appOptions, `blitz-store-${process.pid}-${Date.now()}`);
    const result = await runStoreAction({
      db: firestore,
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
    outcome = {
      result: {
        target: opts.target,
        ...result,
        ...(opts.target === 'production' ? { operatorIdentityBound: true } : {}),
        ...(input ? { inputFileSha256: input.fileSha256 } : {}),
      },
    };
  } catch (error) {
    // SDK errors can carry uids, emails or response bodies. Only fixed codes leave.
    outcome = { error: error instanceof StoreRefusal ? error : new StoreRefusal('STORE_OPERATION_FAILED') };
  }
  // R4: cleanup never decides the outcome. Each step is attempted, bounded and
  // contained; a failure is reported alongside the outcome, never instead of it,
  // and never as complete success (see completionExitCode).
  const cleanupFailures = await runCleanupSteps([
    firestore && ['FIRESTORE_TERMINATE', () => firestore.terminate()],
    app && ['APP_DELETE', () => deleteApp(app)],
    lock && ['LOCK_RELEASE', () => lock.release()],
  ]);
  if (outcome.error) {
    if (cleanupFailures.length) Object.assign(outcome.error, { cleanupComplete: false, cleanupFailures });
    throw outcome.error;
  }
  return cleanupFailures.length ? { ...outcome.result, cleanupComplete: false, cleanupFailures } : outcome.result;
}

const CLEANUP_STEP_MS = 3000;
// Fixed codes only: errors can carry paths or SDK text and are never printed.
const LOCK_FAILURE = /^LOCK_RELEASE_[A-Z_]+$/;

// Runs every [name, step] even if an earlier one fails or hangs, and returns
// the fixed codes of those that did not complete (empty: all completed). A lock
// release that throws one of operator-lock's LOCK_RELEASE_* codes keeps that code.
export async function runCleanupSteps(steps) {
  const failures = [];
  for (const entry of steps) {
    if (!entry) continue;
    const [name, step] = entry;
    let timer;
    try {
      const finished = await Promise.race([
        Promise.resolve().then(step).then(() => true),
        new Promise((resolve) => { timer = setTimeout(() => resolve(false), CLEANUP_STEP_MS); }),
      ]);
      if (!finished) failures.push(`${name}_TIMEOUT`);
    } catch (error) {
      const code = error instanceof LockRefusal && LOCK_FAILURE.test(error.code) ? error.code : `${name}_FAILED`;
      failures.push(code);
    } finally {
      clearTimeout(timer);
    }
  }
  return failures;
}

// Boolean form, kept for callers that only need complete/incomplete.
export async function runCleanup(steps) {
  const failures = await runCleanupSteps(steps.map((step, index) => step && [`STEP_${index}`, step]));
  return failures.length === 0;
}

// 1 is the only code that means nothing was written. Every other non-zero code
// is printed as STORE_UNRESOLVED so it is never mistaken for a refusal.
export function exitCodeFor(error) {
  if (error?.outcome === 'unknown') return 3;
  if (error?.outcome === 'committed-eligibility-changed') return 4;
  if (error?.outcome === 'committed-verified') return 5;
  return 1;
}

// R4: the process exit code. Cleanup that did not complete (for example an
// operator lock that may still be held) adds 10, so it is never 0 and never
// equal to the same outcome with clean cleanup: 10 completed, 11 refused,
// 13 unknown, 14 eligibility changed, 15 receipt failed after commit.
export const CLEANUP_INCOMPLETE_OFFSET = 10;
export function completionExitCode({ result, error } = {}) {
  if (error !== undefined) {
    const base = error instanceof StoreRefusal ? exitCodeFor(error) : 1;
    return error?.cleanupComplete === false ? base + CLEANUP_INCOMPLETE_OFFSET : base;
  }
  return result?.cleanupComplete === false ? CLEANUP_INCOMPLETE_OFFSET : 0;
}

function cleanupSuffix(failures) {
  const codes = Array.isArray(failures) ? failures.filter((code) => /^[A-Z0-9_]{1,64}$/.test(code)) : [];
  return codes.length ? ` ${codes.join(' ')}` : '';
}

export function failureLine(error) {
  const code = error instanceof StoreRefusal ? error.code : 'STORE_OPERATION_FAILED';
  const cleanup = error?.cleanupComplete === false ? ` CLEANUP_INCOMPLETE${cleanupSuffix(error.cleanupFailures)}` : '';
  return `${exitCodeFor(error) === 1 ? 'STORE_REFUSED' : 'STORE_UNRESOLVED'} ${code}${cleanup}`;
}

// R4: printed on stderr beside a successful JSON result whose cleanup did not
// complete. The outcome on stdout stands; the run did not finish cleanly.
export function cleanupIncompleteLine(result) {
  return `STORE_CLEANUP_INCOMPLETE${cleanupSuffix(result?.cleanupFailures)} outcome=${/^[a-z-]{1,40}$/.test(result?.outcome || '') ? result.outcome : (result?.dryRun ? 'dry-run' : 'unreported')} do-not-rerun-apply`;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().then((result) => {
    console.log(JSON.stringify(result));
    if (result?.cleanupComplete === false) console.error(cleanupIncompleteLine(result));
    process.exit(completionExitCode({ result }));
  }).catch((error) => {
    console.error(failureLine(error));
    process.exit(completionExitCode({ error }));
  });
}
