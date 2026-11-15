#!/usr/bin/env node
// Step D operator CLI for the one private campaign document. See secure/STEP_D_CAMPAIGN_STORE.md.
//
//   node scripts/blitz-campaign-store.mjs inspect --target <emulator|production> --project <id>
//   node scripts/blitz-campaign-store.mjs write   --target ... --project ... --input <envelope.json> [--expect-current <digest|none>] [--backup <file>] [--apply]
//   node scripts/blitz-campaign-store.mjs retract --target ... --project ... [--expect-current <digest>] [--backup <file>] [--apply]
//
// Identity and approval come from the environment, never argv (shell history, ps):
//   BLITZ_STORE_UID, BLITZ_STORE_CONFIRM_UID, BLITZ_STORE_APPROVAL
// All arguments and variables are validated before the Admin SDK is loaded.
// Output is JSON with booleans and envelope digests only.
import { createHash } from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  assertNotPublicBundle,
  assertTarget,
  campaignPath,
  envelopeDigest,
  MAX_ENVELOPE_BYTES,
  parseEnvelopeText,
  runStoreAction,
  StoreRefusal,
} from '../secure/campaign-store.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const VALUE_FLAGS = new Set(['--target', '--project', '--input', '--expect-current', '--backup']);

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
  if (action === 'inspect') need(!opts.apply && !opts.backup && !opts.expectCurrent, 'STORE_INSPECT_IS_READ_ONLY');
  return opts;
}

export function outsideRepository(absolute, code, root = ROOT) {
  const relative = path.relative(root, absolute);
  need(relative !== '' && (relative.startsWith('..') || path.isAbsolute(relative)), code);
  return absolute;
}

async function resolveInput(file) {
  let real;
  try {
    real = await fs.realpath(file);
  } catch {
    throw new StoreRefusal('STORE_INPUT_UNREADABLE');
  }
  outsideRepository(real, 'STORE_INPUT_INSIDE_REPOSITORY');
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

async function resolveBackup(file) {
  const absolute = path.resolve(file);
  let dir;
  try {
    dir = await fs.realpath(path.dirname(absolute));
  } catch {
    throw new StoreRefusal('STORE_BACKUP_DIRECTORY_MISSING');
  }
  const target = path.join(dir, path.basename(absolute));
  outsideRepository(target, 'STORE_BACKUP_INSIDE_REPOSITORY');
  const exists = await fs.lstat(target).then(() => true, () => false);
  need(!exists, 'STORE_BACKUP_EXISTS');
  return target;
}

// Exclusive create, mode 600, then re-read: the digest proves what is on disk.
export async function writeBackupFile(file, envelope) {
  await fs.writeFile(file, `${JSON.stringify(envelope)}\n`, { flag: 'wx', mode: 0o600 });
  return envelopeDigest(parseEnvelopeText(await fs.readFile(file, 'utf8')));
}

export async function main(argv = process.argv.slice(2), env = process.env) {
  const opts = parseArgs(argv);
  assertTarget({ target: opts.target, projectId: opts.project, env });
  const uid = env.BLITZ_STORE_UID;
  campaignPath(uid);
  if (opts.action === 'write') need(opts.input, 'STORE_INPUT_REQUIRED');
  const input = opts.action === 'write' ? await resolveInput(opts.input) : null;
  const backupPath = opts.backup && opts.apply ? await resolveBackup(opts.backup) : opts.backup;

  const { initializeApp, deleteApp, applicationDefault } = await import('firebase-admin/app');
  const { getFirestore } = await import('firebase-admin/firestore');
  const { getAuth } = await import('firebase-admin/auth');
  const appOptions = opts.target === 'production'
    ? { projectId: opts.project, credential: applicationDefault() }
    : { projectId: opts.project };
  const app = initializeApp(appOptions, `blitz-store-${process.pid}-${Date.now()}`);
  try {
    const result = await runStoreAction({
      db: getFirestore(app),
      auth: getAuth(app),
      backup: { write: writeBackupFile },
      target: opts.target,
      action: opts.action,
      uid,
      confirmUid: env.BLITZ_STORE_CONFIRM_UID,
      approval: env.BLITZ_STORE_APPROVAL,
      input: input?.envelope ?? null,
      expectCurrent: opts.expectCurrent,
      backupPath,
      apply: opts.apply,
    });
    return { target: opts.target, ...result, ...(input ? { inputFileSha256: input.fileSha256 } : {}) };
  } catch (error) {
    // SDK errors can carry uids, emails or response bodies. Only fixed codes leave.
    if (error instanceof StoreRefusal) throw error;
    throw new StoreRefusal('STORE_OPERATION_FAILED');
  } finally {
    await Promise.race([deleteApp(app), new Promise((resolve) => setTimeout(resolve, 3000))]);
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().then((result) => {
    console.log(JSON.stringify(result));
    process.exit(0);
  }).catch((error) => {
    const code = error instanceof StoreRefusal ? error.code : 'STORE_OPERATION_FAILED';
    console.error(`STORE_REFUSED ${code}`);
    process.exit(1);
  });
}
