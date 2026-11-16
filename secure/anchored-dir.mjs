// R6: directory-anchored creation of private files (backup, receipt).
//
// Problem: the backup/receipt directory is checked when a run starts, but files
// are created later. A path-based open re-resolves every path component, so a
// same-user process that swaps the directory (or an ancestor) for a symlink
// redirects the create into the public repository. O_NOFOLLOW only protects
// the last component, and later path snapshots cannot prove where an inode was
// created. Node has no openat(2)/renameat(2).
//
// Mechanism: every path operation is made relative to the process working
// directory. A relative path is resolved by the kernel from the cwd *object*
// (openat(AT_FDCWD, name)), not from a path string, on Linux and macOS alike.
// The cwd is entered by path, but accepted only if `stat('.')` has the
// device/inode of a directory descriptor that has been held open since the
// directory was first verified (holding it pins that inode: it cannot be freed
// and reused). Then create, lstat, rename and unlink use a bare file name, so
// they act in exactly that directory whatever happens to any path meanwhile.
// All such operations are serialised (cwd is process-wide) and the previous
// cwd is restored afterwards. Contents are written only through the
// descriptor returned by the anchored O_CREAT|O_EXCL|O_NOFOLLOW open.
//
// Location: at verification, before each content write and after it, the
// directory's current location is taken from the kernel (`realpath('.')`, i.e.
// getcwd of the object) and must be outside the repository, by path segment
// and by file identity of every ancestor; the directory must still be private
// (owned by this uid, no group/other bits).
//
// Hard links: a same-user process can `ln` any file it can name, and nothing a
// tool does on the same filesystem prevents that. So, immediately before and
// after every content write, the file must have exactly one link and that link
// must be the anchored name. If either check fails, the inode is truncated to
// zero bytes through the descriptor (emptying every name it has, including one
// planted in the repository) and synced, and the operation refuses.
//
// Trust boundary (what this can and cannot prevent):
//   Prevents: a symlink/rename/replace of the directory path or any ancestor
//     redirecting a create, rename or unlink; creating over or writing into an
//     existing entry (O_EXCL, O_NOFOLLOW); content left behind in a file that,
//     at a check point, has a second link or is no longer the anchored name;
//     writing while the directory object itself is located in the repository.
//   Residual: an empty, exclusively created file (never an overwrite) may be
//     left in the anchored directory, wherever a same-user process has moved
//     that directory object. Content can be visible through a link planted in
//     the microseconds between the pre-write check and the post-write check;
//     it is then truncated and the run refuses.
//   Out of scope: any same-user process can read or copy the operator's private
//     files, read /proc/<pid>/fd or ptrace this process, or move/link the
//     private directory or its files anywhere after this tool has checked them.
//     Such a process already has the data; no file API can stop it.
//   Not covered here: the operator lock file (secure/operator-lock.mjs).
import { constants as fsConstants } from 'node:fs';
import fs from 'node:fs/promises';
import path from 'node:path';

export class PrivatePathChanged extends Error {
  constructor() {
    super('PRIVATE_PATH_CHANGED');
    this.code = 'PRIVATE_PATH_CHANGED';
  }
}

const sameFile = (a, b) => a.dev === b.dev && a.ino === b.ino;
const NAME = /^[^/\0]{1,255}$/;

export function privateDirectoryInfo(info) {
  if (!info.isDirectory() || info.isSymbolicLink()) return false;
  if (typeof process.getuid === 'function' && info.uid !== process.getuid()) return false;
  return (info.mode & 0o077) === 0;
}

function assertName(name) {
  if (!NAME.test(name) || name === '.' || name === '..') throw new PrivatePathChanged();
}

// cwd is process-wide: one anchored section at a time.
let queue = Promise.resolve();
function serialised(fn) {
  const run = queue.then(fn, fn);
  queue = run.catch(() => {});
  return run;
}

export class AnchoredDirectory {
  // `isOutside(realPath)` resolves if the directory's current real path is
  // outside the repository and rejects otherwise. `hooks` are test-only
  // in-process callbacks at each await boundary (never reachable from argv/env).
  constructor({ dirPath, handle, identity, isOutside, hooks }) {
    this.dirPath = dirPath;
    this.handle = handle;
    this.identity = identity;
    this.isOutside = isOutside;
    this.hooks = hooks || {};
  }

  static async open(dirPath, { isOutside, hooks } = {}) {
    if (!path.isAbsolute(dirPath) || typeof isOutside !== 'function') throw new PrivatePathChanged();
    const { O_RDONLY, O_DIRECTORY, O_NOFOLLOW } = fsConstants;
    let handle;
    try {
      handle = await fs.open(dirPath, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    } catch {
      throw new PrivatePathChanged();
    }
    try {
      const identity = await handle.stat();
      if (!privateDirectoryInfo(identity)) throw new PrivatePathChanged();
      const dir = new AnchoredDirectory({ dirPath, handle, identity, isOutside, hooks });
      // The descriptor was opened by path; prove where the object it names is.
      await dir.#anchored(async () => {});
      return dir;
    } catch (error) {
      await handle.close().catch(() => {});
      throw error instanceof PrivatePathChanged ? error : new PrivatePathChanged();
    }
  }

  async #hook(name, detail) {
    if (typeof this.hooks[name] === 'function') await this.hooks[name](detail);
  }

  // Enter the directory, prove the cwd object is the held one and is located
  // outside the repository, run `fn` (which uses bare names only), restore cwd.
  #anchored(fn) {
    return serialised(async () => {
      const previous = process.cwd();
      try {
        try {
          process.chdir(this.dirPath);
        } catch {
          throw new PrivatePathChanged();
        }
        await this.#assertHere();
        await this.#hook('afterAnchor');
        return await fn();
      } finally {
        try { process.chdir(previous); } catch { /* relative paths are never used outside this module */ }
      }
    });
  }

  // Inside an anchored section only.
  async #assertHere() {
    let here;
    let real;
    try {
      here = await fs.stat('.');
      real = await fs.realpath('.');
    } catch {
      throw new PrivatePathChanged();
    }
    if (!sameFile(here, this.identity) || !privateDirectoryInfo(here)) throw new PrivatePathChanged();
    try {
      await this.isOutside(real);
    } catch {
      throw new PrivatePathChanged();
    }
  }

  // Inside an anchored section only: `handle` is the one link, named `name`,
  // in this directory, which is still the held, private, outside directory.
  async #assertSoleLink(handle, name) {
    await this.#assertHere();
    let opened;
    let atName;
    try {
      opened = await handle.stat();
      atName = await fs.lstat(name);
    } catch {
      throw new PrivatePathChanged();
    }
    if (!(opened.isFile() && opened.nlink === 1 && atName.isFile() && sameFile(atName, opened))) throw new PrivatePathChanged();
    return opened;
  }

  // Exclusive create of a new empty regular file with mode 600, in this
  // directory. Never follows or replaces an existing entry (EEXIST propagates).
  async #create(name, read) {
    const { O_CREAT, O_EXCL, O_NOFOLLOW, O_WRONLY, O_RDWR } = fsConstants;
    const handle = await fs.open(name, (read ? O_RDWR : O_WRONLY) | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600);
    try {
      await this.#hook('afterCreate', { name });
      const opened = await handle.stat();
      await this.#hook('afterFirstFstat', { name, opened });
      if (!opened.isFile() || opened.size !== 0) throw new PrivatePathChanged();
      await this.#assertSoleLink(handle, name);
      return handle;
    } catch (error) {
      await handle.close().catch(() => {});
      throw error instanceof PrivatePathChanged ? error : new PrivatePathChanged();
    }
  }

  // Writes `data` through `handle` only after proving the sole link, proves it
  // again afterwards, and empties the inode if anything is wrong.
  async #writeProven(handle, name, data) {
    let wrote = false;
    try {
      await this.#assertSoleLink(handle, name);
      await this.#hook('beforeWrite', { name });
      wrote = true;
      let offset = 0;
      while (offset < data.length) {
        const { bytesWritten } = await handle.write(data, offset, data.length - offset, offset);
        offset += bytesWritten;
      }
      await handle.sync();
      await this.#hook('afterWrite', { name });
      return await this.#assertSoleLink(handle, name);
    } catch (error) {
      if (wrote) await emptyInode(handle);
      throw error instanceof PrivatePathChanged ? error : new PrivatePathChanged();
    }
  }

  // Creates `name` and writes `text` (utf8). With readBack, re-reads the bytes
  // through the same descriptor and returns them.
  async createWithContent(name, text, { readBack = false } = {}) {
    assertName(name);
    const data = Buffer.from(text, 'utf8');
    return this.#anchored(async () => {
      const handle = await this.#create(name, readBack);
      try {
        const written = await this.#writeProven(handle, name, data);
        let back = null;
        if (readBack) {
          const buffer = Buffer.alloc(written.size);
          let offset = 0;
          while (offset < written.size) {
            const { bytesRead } = await handle.read(buffer, offset, written.size - offset, offset);
            if (bytesRead === 0) break;
            offset += bytesRead;
          }
          back = buffer.subarray(0, offset);
        }
        await this.handle.sync();
        return back;
      } finally {
        await handle.close().catch(() => {});
      }
    });
  }

  // Replaces `name` atomically: a new exclusive temp file in this directory,
  // proven and written, then renamed over `name` within this directory, then
  // proven to be the sole link at `name`. Never writes into the old file.
  async replaceWithContent(name, tempName, text) {
    assertName(name);
    assertName(tempName);
    const data = Buffer.from(text, 'utf8');
    return this.#anchored(async () => {
      const handle = await this.#create(tempName, false);
      try {
        await this.#writeProven(handle, tempName, data);
        try {
          await this.#assertSoleLink(handle, tempName);
          await this.#hook('beforeRename', { name, tempName });
          await fs.rename(tempName, name);
          await this.#hook('afterRename', { name });
          await this.#assertSoleLink(handle, name);
        } catch (error) {
          await emptyInode(handle);
          throw error instanceof PrivatePathChanged ? error : new PrivatePathChanged();
        }
        await this.handle.sync();
      } finally {
        await handle.close().catch(() => {});
      }
    });
  }

  async close() {
    await this.handle.close().catch(() => {});
  }
}

async function emptyInode(handle) {
  try {
    await handle.truncate(0);
    await handle.sync();
  } catch { /* the refusal stands */ }
}
