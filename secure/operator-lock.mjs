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
import { constants as fsConstants } from 'node:fs';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

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

// Real path of `target`, resolving the deepest ancestor that exists.
async function realpathAllowMissing(target) {
  const rest = [];
  let current = path.resolve(target);
  for (;;) {
    try {
      return path.join(await fs.realpath(current), ...rest.reverse());
    } catch {
      const parent = path.dirname(current);
      if (parent === current) return path.resolve(target);
      rest.push(path.basename(current));
      current = parent;
    }
  }
}

async function privateDirectory(dir) {
  // Checked before anything is created: the lock never lives in a checkout.
  const real = await realpathAllowMissing(dir);
  const repo = await fs.realpath(REPO_ROOT);
  const relative = path.relative(repo, real);
  if (relative === '' || !(relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative))) {
    throw new LockRefusal('LOCK_DIRECTORY_INSIDE_REPOSITORY');
  }
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  const info = await fs.lstat(dir);
  if (!info.isDirectory()) throw new LockRefusal('LOCK_DIRECTORY_NOT_A_DIRECTORY');
  if (typeof process.getuid === 'function' && info.uid !== process.getuid()) throw new LockRefusal('LOCK_DIRECTORY_NOT_OWNED');
  if ((info.mode & 0o077) !== 0) throw new LockRefusal('LOCK_DIRECTORY_NOT_PRIVATE');
  return fs.realpath(dir);
}

// R4: release() either removes exactly the lock this holder created, or throws
// one of these fixed codes and leaves whatever is there. It never reports a
// release it could not confirm.
export const LOCK_RELEASE_CODES = Object.freeze([
  'LOCK_RELEASE_MISSING', // the lock file is gone: someone else removed it
  'LOCK_RELEASE_UNREADABLE', // it could not be read (EIO, EACCES, ...)
  'LOCK_RELEASE_NOT_OWNED', // it is not the file/nonce this holder created
  'LOCK_RELEASE_UNLINK_FAILED', // ours, but removing it failed
]);

const sameFile = (a, b) => a.dev === b.dev && a.ino === b.ino;

// `io` is the filesystem used by release(); tests inject real-call failures
// through it. It is an in-process dependency, never reachable from argv/env.
export async function acquireOperatorLock({ project, purpose, dir = lockDirectory(), io = fs }) {
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
  let created;
  try {
    await handle.writeFile(`${JSON.stringify({ purpose, pid: process.pid, startedAt: new Date().toISOString(), nonce })}\n`);
    await handle.sync();
    created = await handle.stat();
  } finally {
    await handle.close();
  }
  let released = false;
  return {
    file,
    async release() {
      if (released) return;
      // Only remove the lock this holder created, and only after proving it:
      // the same file (dev/ino) before and after reading our nonce from it.
      let before;
      try {
        before = await io.lstat(file);
      } catch (error) {
        throw new LockRefusal(error?.code === 'ENOENT' ? 'LOCK_RELEASE_MISSING' : 'LOCK_RELEASE_UNREADABLE');
      }
      if (!before.isFile() || !sameFile(before, created)) throw new LockRefusal('LOCK_RELEASE_NOT_OWNED');
      let text;
      try {
        text = await io.readFile(file, { encoding: 'utf8', flag: fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW });
      } catch (error) {
        throw new LockRefusal(error?.code === 'ENOENT' ? 'LOCK_RELEASE_MISSING' : 'LOCK_RELEASE_UNREADABLE');
      }
      if (typeof text !== 'string' || !text.includes(`"nonce":"${nonce}"`)) throw new LockRefusal('LOCK_RELEASE_NOT_OWNED');
      let after;
      try {
        after = await io.lstat(file);
      } catch (error) {
        throw new LockRefusal(error?.code === 'ENOENT' ? 'LOCK_RELEASE_MISSING' : 'LOCK_RELEASE_UNREADABLE');
      }
      if (!sameFile(after, before)) throw new LockRefusal('LOCK_RELEASE_NOT_OWNED');
      try {
        await io.unlink(file);
      } catch {
        throw new LockRefusal('LOCK_RELEASE_UNLINK_FAILED');
      }
      released = true;
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
