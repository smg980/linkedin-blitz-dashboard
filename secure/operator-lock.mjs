// Coordinated operator control for the Auth claim-change race.
//
// Firestore transactions cannot see Auth, and setCustomUserClaims has no
// compare-and-swap. So a Step D write and a D0 claim change for the same
// project must never overlap. Every mutating tool takes this exclusive,
// per-project lock first; the D0 production runbook holds it with
// `node scripts/blitz-operator-lock.mjs hold --project <id>` while claims change.
//
// The lock lives in a private directory (mode 700, owned by the operator,
// outside any checkout). It is never broken automatically: a stale lock is a
// stop for a human, who confirms no other run is active and removes it.
import { randomBytes } from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

export class LockRefusal extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

const PROJECT = /^[a-z0-9-]{1,63}$/;

export function lockDirectory(env = process.env) {
  return env.BLITZ_OPERATOR_LOCK_DIR || path.join(os.homedir(), '.blitz-operator');
}

async function privateDirectory(dir) {
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  const info = await fs.lstat(dir);
  if (!info.isDirectory()) throw new LockRefusal('LOCK_DIRECTORY_NOT_A_DIRECTORY');
  if (typeof process.getuid === 'function' && info.uid !== process.getuid()) throw new LockRefusal('LOCK_DIRECTORY_NOT_OWNED');
  if ((info.mode & 0o077) !== 0) throw new LockRefusal('LOCK_DIRECTORY_NOT_PRIVATE');
  return fs.realpath(dir);
}

export async function acquireOperatorLock({ project, purpose, dir = lockDirectory() }) {
  if (!PROJECT.test(project || '')) throw new LockRefusal('LOCK_INVALID_PROJECT');
  if (!/^[a-z0-9-]{1,40}$/.test(purpose || '')) throw new LockRefusal('LOCK_INVALID_PURPOSE');
  const real = await privateDirectory(dir);
  const file = path.join(real, `${project}.lock`);
  const nonce = randomBytes(16).toString('hex');
  let handle;
  try {
    handle = await fs.open(file, 'wx', 0o600);
  } catch (error) {
    if (error?.code === 'EEXIST') throw new LockRefusal('LOCK_HELD');
    throw new LockRefusal('LOCK_UNAVAILABLE');
  }
  try {
    await handle.writeFile(`${JSON.stringify({ purpose, pid: process.pid, startedAt: new Date().toISOString(), nonce })}\n`);
    await handle.sync();
  } finally {
    await handle.close();
  }
  let released = false;
  return {
    file,
    async release() {
      if (released) return;
      released = true;
      // Only remove the lock this holder created.
      const text = await fs.readFile(file, 'utf8').catch(() => '');
      if (text.includes(`"nonce":"${nonce}"`)) await fs.rm(file, { force: true });
    },
  };
}

export async function withOperatorLock(options, fn) {
  const lock = await acquireOperatorLock(options);
  try {
    return await fn(lock);
  } finally {
    await lock.release();
  }
}
