// R6: unit tests for secure/anchored-dir.mjs. Real directories, renames and
// symlinks only; fictional content.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { AnchoredDirectory, PrivatePathChanged } from '../secure/anchored-dir.mjs';

const outside = async () => true;
const changed = (e) => e instanceof PrivatePathChanged;

async function privateDir(prefix) {
  const dir = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), prefix)));
  await fs.chmod(dir, 0o700);
  return dir;
}

test('R6 anchor: concurrent sections in two directories land in the right place and restore cwd', async () => {
  const a = await privateDir('blitz-anchor-a-');
  const b = await privateDir('blitz-anchor-b-');
  const cwd = process.cwd();
  try {
    const da = await AnchoredDirectory.open(a, { isOutside: outside });
    const db = await AnchoredDirectory.open(b, { isOutside: outside });
    await Promise.all([
      ...Array.from({ length: 8 }, (_, i) => da.createWithContent(`a${i}.json`, `a${i}\n`)),
      ...Array.from({ length: 8 }, (_, i) => db.createWithContent(`b${i}.json`, `b${i}\n`)),
      db.replaceWithContent('b0.json', 'b0.tmp', 'b0-replaced\n'),
    ]);
    assert.equal(process.cwd(), cwd);
    assert.deepEqual((await fs.readdir(a)).sort(), Array.from({ length: 8 }, (_, i) => `a${i}.json`).sort());
    assert.deepEqual((await fs.readdir(b)).sort(), Array.from({ length: 8 }, (_, i) => `b${i}.json`).sort());
    assert.match(await fs.readFile(path.join(b, 'b0.json'), 'utf8'), /^b0(-replaced)?\n$/);
    for (const name of await fs.readdir(a)) assert.equal((await fs.stat(path.join(a, name))).mode & 0o777, 0o600);
    await da.close();
    await db.close();
  } finally {
    await fs.rm(a, { recursive: true, force: true });
    await fs.rm(b, { recursive: true, force: true });
  }
});

test('R6 anchor: an existing entry is never overwritten or followed; names are single components', async () => {
  const dir = await privateDir('blitz-anchor-x-');
  const victim = await privateDir('blitz-anchor-victim-');
  try {
    const d = await AnchoredDirectory.open(dir, { isOutside: outside });
    await fs.writeFile(path.join(victim, 'v.txt'), 'original\n');
    await fs.symlink(path.join(victim, 'v.txt'), path.join(dir, 'link.json'));
    await fs.writeFile(path.join(dir, 'file.json'), 'existing\n');
    await assert.rejects(d.createWithContent('link.json', 'x'));
    await assert.rejects(d.createWithContent('file.json', 'x'));
    assert.equal(await fs.readFile(path.join(victim, 'v.txt'), 'utf8'), 'original\n');
    assert.equal(await fs.readFile(path.join(dir, 'file.json'), 'utf8'), 'existing\n');
    for (const bad of ['', '.', '..', 'a/b', `../${path.basename(victim)}/v.txt`]) await assert.rejects(d.createWithContent(bad, 'x'), changed);
    await d.close();
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
    await fs.rm(victim, { recursive: true, force: true });
  }
});

test('R6 anchor: once the path no longer names the held directory, nothing is created anywhere', async () => {
  const dir = await privateDir('blitz-anchor-s-');
  const elsewhere = await privateDir('blitz-anchor-elsewhere-');
  try {
    const d = await AnchoredDirectory.open(dir, { isOutside: outside });
    await fs.rename(dir, `${dir}.moved`);
    await fs.symlink(elsewhere, dir, 'dir');
    await assert.rejects(d.createWithContent('r.json', 'secret\n'), changed);
    assert.deepEqual(await fs.readdir(elsewhere), []);
    assert.deepEqual(await fs.readdir(`${dir}.moved`), []);
    await fs.unlink(dir);
    // Replaced by a different directory at the same path (same mode, owner).
    await fs.mkdir(dir, { mode: 0o700 });
    await assert.rejects(d.createWithContent('r.json', 'secret\n'), changed);
    assert.deepEqual(await fs.readdir(dir), []);
    await d.close();
  } finally {
    for (const p of [dir, `${dir}.moved`, elsewhere]) await fs.rm(p, { recursive: true, force: true });
  }
});

test('R6 anchor: a directory that is not private, or whose location is refused, is not anchored', async () => {
  const dir = await privateDir('blitz-anchor-p-');
  try {
    await assert.rejects(AnchoredDirectory.open(dir, { isOutside: async () => { throw new Error('inside'); } }), changed);
    await assert.rejects(AnchoredDirectory.open(path.relative(process.cwd(), dir) || '.', { isOutside: outside }), changed);
    await fs.chmod(dir, 0o750);
    await assert.rejects(AnchoredDirectory.open(dir, { isOutside: outside }), changed);
    await fs.chmod(dir, 0o700);
    const d = await AnchoredDirectory.open(dir, { isOutside: outside });
    await fs.chmod(dir, 0o755);
    await assert.rejects(d.createWithContent('r.json', 'x'), changed, 'privacy is re-checked in every section');
    await d.close();
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});
