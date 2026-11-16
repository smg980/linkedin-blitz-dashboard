// The private-only Step D export wrapper. Fictional campaign source only.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { decryptEnvelope } from '../secure/envelope.mjs';
import { envelopeDigest, parseEnvelopeText } from '../secure/campaign-store.mjs';
import { exportPrivateEnvelope } from '../scripts/export-private-envelope.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PASS = 'synthetic-export-passphrase';

async function privateDir(prefix) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), prefix));
  await fs.chmod(dir, 0o700);
  return dir;
}

async function fictionalSource(dir) {
  await fs.writeFile(path.join(dir, 'campaign.json'), JSON.stringify({
    name: 'EXAMPLE Export Campaign', start: '2026-11-16', end: '2026-11-20', plan: {}, rules: ['EXAMPLE only'], accounts: ['EXAMPLE Export Co'],
  }));
  await fs.writeFile(path.join(dir, 'activity_log.csv'), [
    'key,account,contact,confirmation_status,due_date',
    'EXP-ADA-20261117-CONNECT,EXAMPLE Export Co,Example Export Ada,Draft Ready,2026-11-17',
    'EXP-BEN-20261118-CONNECT,EXAMPLE Export Co,Example Export Ben,Research Needed,2026-11-18',
    '',
  ].join('\n'));
}

async function sha(file) {
  return createHash('sha256').update(await fs.readFile(file)).digest('hex');
}

function cleanEnv(extra = {}) {
  const env = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (/^BLITZ_|PASSPHRASE|^CI$|^GITHUB_ACTIONS$/.test(key)) continue;
    env[key] = value;
  }
  return { ...env, ...extra };
}

// A throwaway copy of the repository, so the export's before/after fingerprint
// cannot be disturbed by other test files running in parallel.
async function repositoryCopy() {
  const repo = await privateDir('blitz-export-repo-');
  for (const entry of ['scripts', 'secure', 'docs']) await fs.cp(path.join(root, entry), path.join(repo, entry), { recursive: true });
  await fs.copyFile(path.join(root, 'package.json'), path.join(repo, 'package.json'));
  await fs.symlink(path.join(root, 'node_modules'), path.join(repo, 'node_modules'), 'dir');
  const git = (...args) => spawnSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@example.com', ...args], { cwd: repo, encoding: 'utf8' });
  git('init', '-q');
  await fs.writeFile(path.join(repo, '.gitignore'), 'node_modules\n');
  git('add', '-A');
  git('commit', '-qm', 'fixture');
  return repo;
}

test('export writes one strict private envelope outside the repository and leaves docs/ untouched', async () => {
  const repo = await repositoryCopy();
  const source = await privateDir('blitz-export-src-');
  const out = await privateDir('blitz-export-out-');
  try {
    await fictionalSource(source);
    const before = await sha(path.join(repo, 'docs', 'data.enc.json'));
    const result = spawnSync(process.execPath, [path.join(repo, 'scripts', 'export-private-envelope.mjs'), '--out', out], {
      cwd: repo, encoding: 'utf8', timeout: 120000, env: cleanEnv({ BLITZ_DIR: source, DASHBOARD_PASSPHRASE: PASS }),
    });
    assert.equal(result.status, 0, result.stderr);
    const printed = JSON.parse(result.stdout);
    assert.deepEqual(Object.keys(printed).sort(), ['envelopeDigest', 'exported', 'file']);
    assert.doesNotMatch(result.stdout + result.stderr, /Example Export|EXAMPLE Export|synthetic-export-passphrase/);
    assert.deepEqual(await fs.readdir(out), ['data.enc.json']);
    const file = path.join(out, 'data.enc.json');
    assert.equal((await fs.stat(file)).mode & 0o777, 0o600);
    const envelope = parseEnvelopeText(await fs.readFile(file, 'utf8'));
    assert.equal(envelopeDigest(envelope), printed.envelopeDigest);
    const data = await decryptEnvelope(envelope, PASS);
    assert.deepEqual(data.contacts.map((c) => c.contact), ['Example Export Ada', 'Example Export Ben']);
    assert.equal(await sha(path.join(repo, 'docs', 'data.enc.json')), before);
    const status = spawnSync('git', ['status', '--porcelain', '--untracked-files=all'], { cwd: repo, encoding: 'utf8' });
    assert.equal(status.stdout, '');
  } finally {
    await fs.rm(repo, { recursive: true, force: true });
    await fs.rm(source, { recursive: true, force: true });
    await fs.rm(out, { recursive: true, force: true });
  }
});

test('export refuses every unsafe destination, source or setting before building', async () => {
  const source = await privateDir('blitz-export-src-');
  const base = await privateDir('blitz-export-cases-');
  const inside = path.join(root, '..export-boundary-test');
  try {
    await fictionalSource(source);
    await fs.mkdir(inside, { recursive: true, mode: 0o700 });
    const open = path.join(base, 'open');
    await fs.mkdir(open, { mode: 0o755 });
    await fs.chmod(open, 0o755);
    const occupied = path.join(base, 'occupied');
    await fs.mkdir(occupied, { mode: 0o700 });
    await fs.writeFile(path.join(occupied, 'data.enc.json'), '{}');
    const link = path.join(base, 'docs-link');
    await fs.symlink(path.join(root, 'docs'), link, 'dir');
    const good = path.join(base, 'good');
    await fs.mkdir(good, { mode: 0o700 });
    const env = { BLITZ_DIR: source, DASHBOARD_PASSPHRASE: PASS };
    const cases = [
      [{ out: undefined, env }, 'EXPORT_OUT_REQUIRED'],
      [{ out: path.join(base, 'missing'), env }, 'EXPORT_OUT_NOT_A_DIRECTORY'],
      [{ out: path.join(root, 'docs'), env }, 'EXPORT_OUT_INSIDE_REPOSITORY'],
      [{ out: inside, env }, 'EXPORT_OUT_INSIDE_REPOSITORY'],
      [{ out: link, env }, 'EXPORT_OUT_NOT_A_DIRECTORY'],
      [{ out: open, env }, 'EXPORT_OUT_NOT_PRIVATE'],
      [{ out: occupied, env }, 'EXPORT_OUTPUT_EXISTS'],
      [{ out: good, env: { ...env, BLITZ_OUTPUT_DIR: path.join(root, 'docs') } }, 'EXPORT_OUTPUT_DIR_ENV_REFUSED'],
      [{ out: good, env: { BLITZ_DIR: source } }, 'EXPORT_PASSPHRASE_REQUIRED'],
      [{ out: good, env: { ...env, BLITZ_DIR: path.join(root, 'docs') } }, 'EXPORT_SOURCE_INSIDE_REPOSITORY'],
      [{ out: good, env: { ...env, BLITZ_DIR: undefined } }, 'EXPORT_SOURCE_REQUIRED'],
      [{ out: good, env, args: ['--example'] }, 'EXPORT_FLAGS_REFUSED'],
      [{ out: good, env, args: ['--plain-check'] }, 'EXPORT_FLAGS_REFUSED'],
    ];
    for (const [options, code] of cases) {
      await assert.rejects(exportPrivateEnvelope({ args: [], ...options }), { code }, code);
    }
    assert.deepEqual(await fs.readdir(good), []);
    assert.deepEqual(await fs.readdir(inside), []);
  } finally {
    await fs.rm(inside, { recursive: true, force: true });
    await fs.rm(source, { recursive: true, force: true });
    await fs.rm(base, { recursive: true, force: true });
  }
});

// A build that misbehaves (writes into docs/, or leaves plaintext beside the
// envelope) must stop the export and leave nothing private behind.
test('export fails closed when the build touches docs/ or leaves anything but one envelope', async () => {
  const repo = await privateDir('blitz-export-repo-');
  const source = await privateDir('blitz-export-src-');
  const out = await privateDir('blitz-export-out-');
  try {
    await fictionalSource(source);
    await fs.mkdir(path.join(repo, 'docs'));
    await fs.copyFile(path.join(root, 'docs', 'data.enc.json'), path.join(repo, 'docs', 'data.enc.json'));
    const git = (...args) => spawnSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@example.com', ...args], { cwd: repo, encoding: 'utf8' });
    git('init', '-q');
    git('add', '-A');
    git('commit', '-qm', 'fixture');
    const real = path.join(root, 'scripts', 'build.mjs');
    const intoDocs = path.join(repo, 'build-into-docs.mjs');
    await fs.writeFile(intoDocs, `import { spawnSync } from 'node:child_process';
const env = { ...process.env }; delete env.BLITZ_OUTPUT_DIR;
spawnSync(process.execPath, [${JSON.stringify(real)}], { env, stdio: 'ignore' });
`);
    const withPlain = path.join(repo, 'build-with-plain.mjs');
    await fs.writeFile(withPlain, `import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
spawnSync(process.execPath, [${JSON.stringify(real)}], { stdio: 'ignore' });
fs.writeFileSync(process.env.BLITZ_OUTPUT_DIR + '/contacts.plain.json', '{"contact":"Example Export Ada"}');
`);
    git('add', '-A');
    git('commit', '-qm', 'fake builds');
    const env = { BLITZ_DIR: source, DASHBOARD_PASSPHRASE: PASS, PATH: process.env.PATH };
    // build.mjs resolves docs/ from its own location, so point the fake at a copy inside the fixture repo.
    await fs.mkdir(path.join(repo, 'scripts'));
    await fs.copyFile(real, path.join(repo, 'scripts', 'build.mjs'));
    await fs.writeFile(intoDocs, (await fs.readFile(intoDocs, 'utf8')).replace(JSON.stringify(real), JSON.stringify(path.join(repo, 'scripts', 'build.mjs'))));
    git('add', '-A');
    git('commit', '-qm', 'copy build');
    const docsBefore = await sha(path.join(repo, 'docs', 'data.enc.json'));
    await assert.rejects(exportPrivateEnvelope({ out, env, repoRoot: repo, buildScript: intoDocs }), { code: 'EXPORT_PUBLIC_BUNDLE_CHANGED' });
    assert.notEqual(await sha(path.join(repo, 'docs', 'data.enc.json')), docsBefore, 'the fixture build did write into docs/');
    assert.deepEqual(await fs.readdir(out), []);
    git('checkout', '--', 'docs/data.enc.json');
    await assert.rejects(exportPrivateEnvelope({ out, env, repoRoot: repo, buildScript: withPlain }), { code: 'EXPORT_UNEXPECTED_OUTPUT' });
    assert.deepEqual(await fs.readdir(out), [], 'staged plaintext and envelope were removed');
  } finally {
    await fs.rm(repo, { recursive: true, force: true });
    await fs.rm(source, { recursive: true, force: true });
    await fs.rm(out, { recursive: true, force: true });
  }
});
