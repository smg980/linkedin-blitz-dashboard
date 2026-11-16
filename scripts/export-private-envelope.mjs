#!/usr/bin/env node
// Private-only export of the real campaign envelope for Step D.
//
//   BLITZ_DIR=<private source folder> DASHBOARD_PASSPHRASE=<rotated passphrase> \
//     node scripts/export-private-envelope.mjs --out <private folder outside the repo>
//
// scripts/build.mjs writes into the public docs/ folder whenever
// BLITZ_OUTPUT_DIR is unset; that is the GitHub Pages path and stays as is. This
// wrapper is the only supported way to produce the private Step D envelope, and
// it fails closed:
//   - --out must already exist, be a real directory (not a symlink) owned by
//     this user, mode 700 (no group/other access), outside the repository by
//     segment, real path and file identity, with no data.enc.json in it;
//   - BLITZ_DIR must exist outside the repository; BLITZ_OUTPUT_DIR must not be
//     set (only --out decides where output goes); no build flags are accepted;
//   - the build writes into a fresh private staging folder inside --out; it
//     must leave exactly one strict envelope there and nothing else;
//   - docs/data.enc.json and `git status --porcelain` must be byte-identical
//     before and after, or the export stops and the repository needs review.
// Output is the envelope digest only. Nothing is printed from the source.
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { assertNotPublicBundle, envelopeDigest, parseEnvelopeText } from '../secure/campaign-store.mjs';
import { assertOutsideRepository } from './blitz-campaign-store.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

export class ExportRefusal extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

function need(condition, code) {
  if (!condition) throw new ExportRefusal(code);
}

async function privateDirectory(dir, code, repoRoot) {
  need(typeof dir === 'string' && dir.length > 0, `${code}_REQUIRED`);
  const absolute = path.resolve(dir);
  const info = await fs.lstat(absolute).catch(() => null);
  need(info && info.isDirectory() && !info.isSymbolicLink(), `${code}_NOT_A_DIRECTORY`);
  const real = await fs.realpath(absolute);
  try {
    await assertOutsideRepository(real, `${code}_INSIDE_REPOSITORY`, repoRoot);
  } catch (error) {
    throw new ExportRefusal(error.code || `${code}_INSIDE_REPOSITORY`);
  }
  return { real, info };
}

async function fingerprintRepository(repoRoot) {
  const docs = await fs.readFile(path.join(repoRoot, 'docs', 'data.enc.json')).catch(() => Buffer.from('missing'));
  const status = spawnSync('git', ['status', '--porcelain', '--untracked-files=all'], { cwd: repoRoot, encoding: 'utf8' });
  need(status.status === 0, 'EXPORT_GIT_STATUS_UNAVAILABLE');
  return {
    docs: createHash('sha256').update(docs).digest('hex'),
    status: createHash('sha256').update(status.stdout).digest('hex'),
  };
}

export async function exportPrivateEnvelope({
  out,
  env = process.env,
  args = [],
  repoRoot = ROOT,
  buildScript = path.join(ROOT, 'scripts', 'build.mjs'),
}) {
  need(args.length === 0, 'EXPORT_FLAGS_REFUSED');
  need(!env.BLITZ_OUTPUT_DIR, 'EXPORT_OUTPUT_DIR_ENV_REFUSED');
  need(typeof env.DASHBOARD_PASSPHRASE === 'string' && env.DASHBOARD_PASSPHRASE.length >= 12, 'EXPORT_PASSPHRASE_REQUIRED');
  const target = await privateDirectory(out, 'EXPORT_OUT', repoRoot);
  need(typeof process.getuid !== 'function' || target.info.uid === process.getuid(), 'EXPORT_OUT_NOT_OWNED');
  need((target.info.mode & 0o077) === 0, 'EXPORT_OUT_NOT_PRIVATE');
  const finalFile = path.join(target.real, 'data.enc.json');
  need(!(await fs.lstat(finalFile).then(() => true, () => false)), 'EXPORT_OUTPUT_EXISTS');
  await privateDirectory(env.BLITZ_DIR, 'EXPORT_SOURCE', repoRoot);

  const before = await fingerprintRepository(repoRoot);
  const stage = await fs.mkdtemp(path.join(target.real, '.export-'));
  try {
    await fs.chmod(stage, 0o700);
    const childEnv = {};
    for (const [key, value] of Object.entries(env)) {
      if (/^BLITZ_OUTPUT_DIR$|^CI$|^GITHUB_ACTIONS$/.test(key)) continue;
      childEnv[key] = value;
    }
    childEnv.BLITZ_OUTPUT_DIR = stage;
    const build = spawnSync(process.execPath, [buildScript], { cwd: repoRoot, env: childEnv, encoding: 'utf8', timeout: 300000 });
    const after = await fingerprintRepository(repoRoot);
    // Checked even when the build failed: a partial write into docs/ is still a stop.
    need(after.docs === before.docs, 'EXPORT_PUBLIC_BUNDLE_CHANGED');
    need(after.status === before.status, 'EXPORT_REPOSITORY_CHANGED');
    need(build.status === 0, 'EXPORT_BUILD_FAILED');
    const produced = (await fs.readdir(stage)).sort();
    need(JSON.stringify(produced) === JSON.stringify(['data.enc.json']), 'EXPORT_UNEXPECTED_OUTPUT');
    const staged = path.join(stage, 'data.enc.json');
    need((await fs.lstat(staged)).isFile(), 'EXPORT_UNEXPECTED_OUTPUT');
    const envelope = parseEnvelopeText(await fs.readFile(staged, 'utf8'));
    const publicText = await fs.readFile(path.join(repoRoot, 'docs', 'data.enc.json'), 'utf8').catch(() => null);
    if (publicText !== null) assertNotPublicBundle(envelope, parseEnvelopeText(publicText));
    await fs.chmod(staged, 0o600);
    // link() refuses to replace an existing file, so a concurrent writer cannot be overwritten.
    await fs.link(staged, finalFile);
    return { exported: true, file: 'data.enc.json', envelopeDigest: envelopeDigest(envelope) };
  } catch (error) {
    if (error instanceof ExportRefusal) throw error;
    throw new ExportRefusal(error?.code && /^STORE_/.test(error.code) ? error.code : 'EXPORT_FAILED');
  } finally {
    await fs.rm(stage, { recursive: true, force: true });
  }
}

function parseCli(argv) {
  const rest = [];
  let out;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--out' && out === undefined) out = argv[++i];
    else rest.push(argv[i]);
  }
  return { out, args: rest };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const { out, args } = parseCli(process.argv.slice(2));
  exportPrivateEnvelope({ out, args }).then((result) => {
    console.log(JSON.stringify(result));
  }).catch((error) => {
    console.error(`EXPORT_REFUSED ${error instanceof ExportRefusal ? error.code : 'EXPORT_FAILED'}`);
    process.exitCode = 1;
  });
}
