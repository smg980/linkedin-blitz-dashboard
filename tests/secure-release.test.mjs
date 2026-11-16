// F2/F3 unit tests for scripts/secure-release.mjs. Fictional data only.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { appendFile, chmod, mkdtemp, readFile, rm, stat, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildSecureShell } from '../scripts/build-secure-shell.mjs';
import {
  approvedHeaders,
  assertResponseHeaders,
  assertShellHtml,
  assertVersionFiles,
  freezeRelease,
  parseHeaderDump,
  removeRelease,
  verifyFrozen,
} from '../scripts/secure-release.mjs';
import { SECURE_SHELL_FILES } from '../scripts/verify-secure-shell.mjs';
import { FICTIONAL_EXPORT, webConfig } from './helpers/hosting-stubs.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const approved = approvedHeaders(JSON.parse(await readFile(path.join(root, 'firebase.secure-blitz.json'), 'utf8')));

async function productionBuild(dir) {
  const configPath = path.join(dir, 'config.json');
  await writeFile(configPath, JSON.stringify(webConfig()));
  const out = path.join(dir, 'shell');
  await buildSecureShell({ emulator: false, configPath, out });
  return out;
}

async function withRelease(fn) {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'blitz-release-unit-'));
  try {
    const source = await productionBuild(dir);
    return await fn({ dir, source });
  } finally {
    spawnSync('chmod', ['-R', 'u+w', dir]);
    await rm(dir, { recursive: true, force: true });
  }
}

function dump(status, entries) {
  return `HTTP/2 ${status}\r\n${entries.map(([k, v]) => `${k}: ${v}\r\n`).join('')}\r\n`;
}

const good = [['content-type', 'text/html; charset=utf-8'], ...[...approved].map(([k, v]) => [k, v])];

test('freeze copies exactly the allowlist into a private read-only root bound to one manifest digest', async () => {
  await withRelease(async ({ dir, source }) => {
    const { root: release, manifestSha256 } = await freezeRelease({ source, tmpRoot: dir });
    try {
      assert.match(manifestSha256, /^[0-9a-f]{64}$/);
      assert.ok(!release.startsWith(root));
      const manifest = await verifyFrozen(release, manifestSha256);
      assert.deepEqual(manifest.files.map((file) => file.path), SECURE_SHELL_FILES);
      const deployConfig = JSON.parse(await readFile(path.join(release, 'firebase.json'), 'utf8'));
      assert.equal(deployConfig.hosting.public, 'public');
      assert.equal(deployConfig.hosting.target, 'blitz');
      // A later change to the source build has no effect on the frozen copy.
      await appendFile(path.join(source, 'shell.js'), '\n// changed after freeze\n');
      await writeFile(path.join(source, 'contacts-export.json'), FICTIONAL_EXPORT);
      await verifyFrozen(release, manifestSha256);
      assert.equal((await stat(path.join(release, 'public', 'shell.js'))).mode & 0o777, 0o400);
      assert.equal((await stat(path.join(release, 'public'))).mode & 0o777, 0o500);
      assert.equal((await stat(release)).mode & 0o077, 0, 'release root must be private to the operator');
      // root bypasses file modes, so the write refusal is only observable for other users.
      if (process.getuid?.() !== 0) await assert.rejects(writeFile(path.join(release, 'public', 'shell.js'), 'x'), /EACCES|EPERM/);
      await assert.rejects(verifyFrozen(release, '0'.repeat(64)), /recorded digest/);
    } finally {
      await removeRelease(release);
    }
  });
});

test('a frozen release with an added, removed, changed or replaced file fails verification', async () => {
  const faults = {
    added: async (pub) => { await chmod(pub, 0o700); await writeFile(path.join(pub, 'campaign-export.json'), FICTIONAL_EXPORT); },
    hidden: async (pub) => { await chmod(pub, 0o700); await writeFile(path.join(pub, '.contacts.json'), FICTIONAL_EXPORT); },
    nested: async (pub) => { await chmod(path.join(pub, 'img'), 0o700); await writeFile(path.join(pub, 'img', 'ada.png.json'), FICTIONAL_EXPORT); },
    removed: async (pub) => { await chmod(pub, 0o700); await rm(path.join(pub, 'blitz.css')); },
    changed: async (pub) => { await chmod(path.join(pub, 'config.js'), 0o600); await appendFile(path.join(pub, 'config.js'), '\n'); },
    symlinked: async (pub) => { await chmod(pub, 0o700); await rm(path.join(pub, 'shell.css')); await symlink('/etc/hostname', path.join(pub, 'shell.css')); },
    config: async (pub) => { const file = path.join(pub, '..', 'firebase.json'); await chmod(file, 0o600); await appendFile(file, ' '); },
    stray: async (pub) => { await writeFile(path.join(pub, '..', 'notes.txt'), 'x'); },
  };
  for (const [name, fault] of Object.entries(faults)) {
    await withRelease(async ({ dir, source }) => {
      const { root: release, manifestSha256 } = await freezeRelease({ source, tmpRoot: dir });
      try {
        await fault(path.join(release, 'public'));
        await assert.rejects(verifyFrozen(release, manifestSha256), Error, name);
      } finally {
        await removeRelease(release);
      }
    });
  }
});

test('freeze refuses a build with a plaintext export under any name, a symlink, or a root inside the repository', async () => {
  for (const extra of ['contacts-export.json', 'img/logo.png.json', 'fonts/notes.txt', '.campaign.json']) {
    await withRelease(async ({ dir, source }) => {
      await writeFile(path.join(source, extra), FICTIONAL_EXPORT);
      await assert.rejects(freezeRelease({ source, tmpRoot: dir }), /allowlist/, extra);
    });
  }
  await withRelease(async ({ dir, source }) => {
    await rm(path.join(source, 'shell.css'));
    await symlink(path.join(source, 'theme.css'), path.join(source, 'shell.css'));
    await assert.rejects(freezeRelease({ source, tmpRoot: dir }), /non-regular/);
  });
  await withRelease(async ({ source }) => {
    await assert.rejects(freezeRelease({ source, tmpRoot: root }), /outside the repository/);
  });
});

test('Hosting version file lists must be one complete page with exactly the expected paths', () => {
  const entry = (p, patch = {}) => ({ path: `/${p}`, hash: 'a'.repeat(64), status: 'ACTIVE', ...patch });
  const ok = JSON.stringify({ files: SECURE_SHELL_FILES.map((p) => entry(p)) });
  assert.deepEqual(assertVersionFiles(ok, SECURE_SHELL_FILES), SECURE_SHELL_FILES);
  const cases = [
    [{ files: [...SECURE_SHELL_FILES, 'contacts-export.json'].map((p) => entry(p)) }, /outside the approved list/],
    [{ files: SECURE_SHELL_FILES.slice(1).map((p) => entry(p)) }, /missing approved files/],
    [{ files: [...SECURE_SHELL_FILES, 'index.html'].map((p) => entry(p)) }, /twice/],
    [{ files: SECURE_SHELL_FILES.map((p) => entry(p)), nextPageToken: 'more' }, /paged/],
    [{ files: SECURE_SHELL_FILES.map((p) => entry(p, p === 'shell.js' ? { status: 'EXPECTED' } : {})) }, /not ACTIVE/],
    [{ files: SECURE_SHELL_FILES.map((p) => entry(p, p === 'shell.js' ? { path: '/../shell.js' } : {})) }, /invalid path/],
    [{}, /no files array/],
  ];
  for (const [value, pattern] of cases) assert.throws(() => assertVersionFiles(JSON.stringify(value), SECURE_SHELL_FILES), pattern);
  assert.throws(() => assertVersionFiles('not json', SECURE_SHELL_FILES), /not JSON/);
});

test('live responses need status 200, no redirect, and exactly one of each approved security header', () => {
  assert.equal(assertResponseHeaders(dump(200, good), 'index.html', approved), true);
  const csp = approved.get('content-security-policy');
  const swap = (key, value) => good.map(([k, v]) => (k === key ? [k, value] : [k, v]));
  const cases = [
    [dump(200, swap('content-security-policy', csp.replace("script-src 'self'", "script-src 'self' 'unsafe-inline'"))), /content-security-policy header is not the approved value/],
    [dump(200, swap('content-security-policy', csp.replace("script-src 'self'", "script-src 'self' 'unsafe-eval'"))), /not the approved value/],
    [dump(200, swap('content-security-policy', csp.replace("script-src 'self' https://apis.google.com", "script-src 'self' https://apis.google.com https://cdn.example"))), /not the approved value/],
    [dump(200, swap('content-security-policy', csp.replace(" frame-ancestors 'none';", ''))), /not the approved value/],
    [dump(200, good.filter(([k]) => k !== 'x-frame-options')), /exactly one x-frame-options/],
    [dump(200, swap('x-frame-options', 'SAMEORIGIN')), /x-frame-options header is not the approved value/],
    [dump(200, [...good, ['content-security-policy', "default-src *"]]), /exactly one content-security-policy/],
    [dump(200, [...good, ['content-security-policy-report-only', "default-src *"]]), /report-only/],
    [dump(301, [['location', 'https://attacker.example/']]), /HTTP 301/],
    [dump(200, [...good, ['location', 'https://attacker.example/']]), /Location/],
    [`${dump(301, [['location', '/x']])}${dump(200, good)}`, /exactly one HTTP response/],
    [dump(404, []), /HTTP 404/],
    [dump(200, swap('cache-control', 'public, max-age=3600')), /cache-control/],
    [dump(200, swap('content-type', 'text/plain')), /content type/],
  ];
  for (const [text, pattern] of cases) assert.throws(() => assertResponseHeaders(text, 'index.html', approved), pattern);
  assert.equal(parseHeaderDump('HTTP/1.1 200 OK\r\nX-A: 1\r\nx-a: 2\r\n\r\n').headers.get('x-a').length, 2);
});

test('the shell page must carry the exact CSP and load only config.js and shell.js', async () => {
  await withRelease(async ({ source }) => {
    const html = await readFile(path.join(source, 'index.html'), 'utf8');
    assert.equal(assertShellHtml(html), true);
    const cases = [
      [html.replace('</body>', '<script src="analytics.js" defer></script></body>'), /scripts other than/],
      [html.replace('</body>', '<script>window.x=1</script></body>'), /scripts other than|inline/],
      [html.replace('<body ', '<body onload="x()" '), /inline handlers/],
      [html.replace("script-src 'self'", "script-src 'self' 'unsafe-inline'"), /exact production policy/],
      [html.replace(/<meta http-equiv="Content-Security-Policy"[^>]*>/, ''), /exact production policy/],
      [html.replace('</head>', '<meta http-equiv="refresh" content="0;url=https://attacker.example"></head>'), /refresh/],
      [html.replace('</body>', '<iframe src="https://attacker.example"></iframe></body>'), /frames/],
      [html.replace('id="unlock-form"', 'id="x"'), /not the secure shell/],
    ];
    for (const [text, pattern] of cases) assert.throws(() => assertShellHtml(text), pattern);
  });
});

// R1: the Hosting API names files by the SHA-256 of the CLI's gzip stream, not
// of the bytes. The oracle is the pinned firebase-tools Uploader itself.
test('R1: hostingFileHash equals the pinned Firebase CLI upload hash for every shell file and multi-chunk files', async () => {
  const { createRequire } = await import('node:module');
  const { hostingFileHash } = await import('../scripts/secure-release.mjs');
  const { Uploader } = createRequire(import.meta.url)('firebase-tools/lib/deploy/hosting/uploader.js');
  const dir = await mkdtemp(path.join(os.tmpdir(), 'blitz-hosting-hash-'));
  try {
    const pub = await productionBuild(dir);
    const big = path.join(pub, 'big.bin');
    // Several 64 KiB read-stream chunks of incompressible and repetitive data.
    await writeFile(big, Buffer.concat([Buffer.from(Array.from({ length: 300000 }, (_, i) => (i * 7919) % 251)), Buffer.alloc(200000, 0x41)]));
    const files = [...SECURE_SHELL_FILES, 'big.bin'];
    const uploader = new Uploader({ version: 'sites/x/versions/y', public: pub, files, projectRoot: dir, cwd: dir });
    for (const rel of files) {
      await uploader.hashHandler(rel);
      const cli = uploader.pathMap[rel];
      assert.match(cli, /^[0-9a-f]{64}$/);
      assert.equal(await hostingFileHash(path.join(pub, rel)), cli, `${rel} from file`);
      assert.equal(await hostingFileHash(await readFile(path.join(pub, rel))), cli, `${rel} from bytes`);
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
