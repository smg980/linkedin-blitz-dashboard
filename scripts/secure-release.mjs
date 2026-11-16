#!/usr/bin/env node
// F2/F3: an immutable, manifest-bound private-shell release and an exact live
// security baseline. Offline only: the deploy wrapper performs every network
// read (Hosting API, HTTPS fetches) and passes the results in as files.
//
// Release root (mode 700, created under the operator's TMPDIR, never in the repo):
//   public/          frozen copy of the reviewed build (dirs 500, files 400)
//   firebase.json    the approved firebase.secure-blitz.json with public: "public"
//   .firebaserc      the approved .firebaserc
//   manifest.json    canonical JSON: every public file's path, size and SHA-256,
//                    plus the SHA-256 of firebase.json and .firebaserc
// The manifest's own SHA-256 is printed once and held by the wrapper; every
// later check is bound to it.
import { createHash } from 'node:crypto';
import { createReadStream, readFileSync } from 'node:fs';
import { Readable } from 'node:stream';
import zlib from 'node:zlib';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { productionCsp } from '../secure/csp.mjs';
import { DEMO_HOSTING_FILES } from './build-firebase-demo.mjs';
import { assertPrivateWebConfig, assertSecureTarget } from './secure-hosting-guard.mjs';
import { SECURE_SHELL_FILES, verifySecureShell } from './verify-secure-shell.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const RELEASE_PUBLIC = 'public';
const ROOT_ENTRIES = new Set(['public', 'firebase.json', '.firebaserc', 'manifest.json']);
// The Firebase CLI writes its upload hash cache here during deploy. It is never uploaded.
const CLI_CACHE_DIR = '.firebase';
const DIGEST = /^[0-9a-f]{64}$/;
const MAX_FILE_BYTES = 8 * 1024 * 1024;

export function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

// Regular files and directories only. A symlink, socket, FIFO or device anywhere
// in the tree is refused rather than followed.
export async function listTree(dir, relative = '') {
  const entries = await fs.readdir(path.join(dir, relative), { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const rel = path.posix.join(relative, entry.name);
    const info = await fs.lstat(path.join(dir, rel));
    if (info.isDirectory()) files.push(...await listTree(dir, rel));
    else if (info.isFile()) files.push(rel);
    else throw new Error(`Release refuses a non-regular file: ${rel}`);
  }
  return files.sort();
}

export function canonicalManifest({ files, configSha256, rcSha256 }) {
  const sorted = [...files].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  return `${JSON.stringify({
    version: 1,
    configSha256,
    rcSha256,
    files: sorted.map(({ path: p, size, sha256: digest }) => ({ path: p, size, sha256: digest })),
  })}\n`;
}

export function parseManifest(text, expectedSha256) {
  if (!DIGEST.test(expectedSha256 || '')) throw new Error('Expected manifest digest is missing or malformed');
  if (sha256(Buffer.from(text, 'utf8')) !== expectedSha256) throw new Error('Release manifest does not match its recorded digest');
  const manifest = JSON.parse(text);
  if (manifest?.version !== 1 || !Array.isArray(manifest.files)) throw new Error('Unsupported release manifest');
  if (canonicalManifest(manifest) !== text) throw new Error('Release manifest is not canonical');
  const paths = manifest.files.map((file) => file.path);
  if (JSON.stringify(paths) !== JSON.stringify(SECURE_SHELL_FILES)) {
    throw new Error(`Release manifest is not the secure shell allowlist: ${paths.join(', ')}`);
  }
  for (const file of manifest.files) {
    if (!Number.isInteger(file.size) || file.size < 1 || file.size > MAX_FILE_BYTES || !DIGEST.test(file.sha256)) {
      throw new Error(`Release manifest entry is malformed: ${file.path}`);
    }
  }
  if (!DIGEST.test(manifest.configSha256) || !DIGEST.test(manifest.rcSha256)) throw new Error('Release manifest lacks config digests');
  return manifest;
}

export function releaseConfig(approved) {
  const derived = JSON.parse(JSON.stringify(approved));
  derived.hosting.public = RELEASE_PUBLIC;
  return `${JSON.stringify(derived, null, 2)}\n`;
}

async function readRegular(file) {
  const info = await fs.lstat(file);
  if (!info.isFile()) throw new Error(`Release refuses a non-regular file: ${path.basename(file)}`);
  if (info.size > MAX_FILE_BYTES) throw new Error(`Release file is too large: ${path.basename(file)}`);
  return fs.readFile(file);
}

async function makeReadOnly(dir) {
  const entries = await fs.readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) await makeReadOnly(full);
    else await fs.chmod(full, 0o400);
  }
  await fs.chmod(dir, 0o500);
}

// Copies the reviewed build exactly once. The bytes hashed are the bytes written;
// the source directory is never read again.
export async function freezeRelease({ source, repoRoot = ROOT, tmpRoot = os.tmpdir() } = {}) {
  const rc = JSON.parse(await fs.readFile(path.join(repoRoot, '.firebaserc'), 'utf8'));
  const approved = JSON.parse(await fs.readFile(path.join(repoRoot, 'firebase.secure-blitz.json'), 'utf8'));
  assertSecureTarget(rc, approved);
  const listed = await listTree(source);
  if (JSON.stringify(listed) !== JSON.stringify(SECURE_SHELL_FILES)) {
    throw new Error(`Build output is not the secure shell allowlist: ${listed.join(', ')}`);
  }
  const root = await fs.mkdtemp(path.join(tmpRoot, 'blitz-release-'));
  await fs.chmod(root, 0o700);
  try {
    const realRoot = await fs.realpath(root);
    const realRepo = await fs.realpath(repoRoot);
    const rel = path.relative(realRepo, realRoot);
    if (rel === '' || !(rel === '..' || rel.startsWith(`..${path.sep}`) || path.isAbsolute(rel))) {
      throw new Error('Release root must be outside the repository; set TMPDIR elsewhere');
    }
    const pub = path.join(root, RELEASE_PUBLIC);
    await fs.mkdir(pub, { mode: 0o700 });
    const files = [];
    for (const rel of listed) {
      const bytes = await readRegular(path.join(source, rel));
      const dest = path.join(pub, rel);
      await fs.mkdir(path.dirname(dest), { recursive: true, mode: 0o700 });
      await fs.writeFile(dest, bytes, { flag: 'wx', mode: 0o600 });
      files.push({ path: rel, size: bytes.length, sha256: sha256(bytes) });
    }
    // The content checks run on the frozen copy, not on the source.
    const checked = await verifySecureShell(pub);
    if (checked.emulator) throw new Error('Refusing to freeze an emulator shell');
    assertPrivateWebConfig(await fs.readFile(path.join(pub, 'config.js'), 'utf8'));
    const configText = releaseConfig(approved);
    const rcText = `${JSON.stringify(rc, null, 2)}\n`;
    await fs.writeFile(path.join(root, 'firebase.json'), configText, { flag: 'wx', mode: 0o400 });
    await fs.writeFile(path.join(root, '.firebaserc'), rcText, { flag: 'wx', mode: 0o400 });
    const manifestText = canonicalManifest({ files, configSha256: sha256(configText), rcSha256: sha256(rcText) });
    await fs.writeFile(path.join(root, 'manifest.json'), manifestText, { flag: 'wx', mode: 0o400 });
    await makeReadOnly(pub);
    const manifestSha256 = sha256(Buffer.from(manifestText, 'utf8'));
    await verifyFrozen(root, manifestSha256, { repoRoot });
    return { root, manifestSha256 };
  } catch (error) {
    await removeRelease(root);
    throw error;
  }
}

export async function removeRelease(root) {
  if (!root) return;
  await fs.chmod(root, 0o700).catch(() => {});
  const restore = async (dir) => {
    let entries = [];
    try { entries = await fs.readdir(dir, { withFileTypes: true }); } catch { return; }
    await fs.chmod(dir, 0o700).catch(() => {});
    for (const entry of entries) if (entry.isDirectory()) await restore(path.join(dir, entry.name));
  };
  await restore(root);
  await fs.rm(root, { recursive: true, force: true });
}

// Re-hashes every frozen file and both deploy configs against the manifest.
// Any missing, added, replaced or changed file fails.
export async function verifyFrozen(root, manifestSha256, { repoRoot = ROOT } = {}) {
  const top = await fs.readdir(root);
  for (const name of top) {
    if (ROOT_ENTRIES.has(name)) continue;
    if (name === CLI_CACHE_DIR && (await fs.lstat(path.join(root, name))).isDirectory()) continue;
    throw new Error(`Unexpected entry in release root: ${name}`);
  }
  for (const name of ROOT_ENTRIES) {
    if (!top.includes(name)) throw new Error(`Release root is missing ${name}`);
  }
  const manifest = parseManifest((await readRegular(path.join(root, 'manifest.json'))).toString('utf8'), manifestSha256);
  const pub = path.join(root, RELEASE_PUBLIC);
  if (!(await fs.lstat(pub)).isDirectory()) throw new Error('Release public directory was replaced');
  const listed = await listTree(pub);
  const expected = manifest.files.map((file) => file.path);
  const added = listed.filter((rel) => !expected.includes(rel));
  const missing = expected.filter((rel) => !listed.includes(rel));
  if (added.length) throw new Error(`Release has files not in its manifest: ${added.join(', ')}`);
  if (missing.length) throw new Error(`Release is missing manifest files: ${missing.join(', ')}`);
  for (const file of manifest.files) {
    const bytes = await readRegular(path.join(pub, file.path));
    if (bytes.length !== file.size || sha256(bytes) !== file.sha256) throw new Error(`Release file changed after freeze: ${file.path}`);
  }
  const configText = (await readRegular(path.join(root, 'firebase.json'))).toString('utf8');
  const rcText = (await readRegular(path.join(root, '.firebaserc'))).toString('utf8');
  if (sha256(configText) !== manifest.configSha256) throw new Error('Release firebase.json changed after freeze');
  if (sha256(rcText) !== manifest.rcSha256) throw new Error('Release .firebaserc changed after freeze');
  // Bound to the approved commit's own files too, so a matching-but-wrong manifest is refused.
  const approved = JSON.parse(await fs.readFile(path.join(repoRoot, 'firebase.secure-blitz.json'), 'utf8'));
  const rc = JSON.parse(await fs.readFile(path.join(repoRoot, '.firebaserc'), 'utf8'));
  if (configText !== releaseConfig(approved)) throw new Error('Release firebase.json is not the approved config');
  if (rcText !== `${JSON.stringify(rc, null, 2)}\n`) throw new Error('Release .firebaserc is not the approved target map');
  return manifest;
}

// R1: the Hosting API does not report the SHA-256 of a file's bytes. The
// Firebase CLI (firebase-tools 14.22.0, lib/deploy/hosting/uploader.js:
// zipStream + hashHandler) uploads, and names, every file by the SHA-256 of
// its gzip stream at level 9 (zlib.createGzip({ level: 9 }) over a read
// stream). This is that representation, computed the same way. Run it under
// the same Node/zlib as the CLI: a different zlib can compress differently,
// which fails closed (a mismatch stops the run) rather than open.
export const HOSTING_GZIP_LEVEL = 9;

export async function hostingFileHash(source) {
  const input = Buffer.isBuffer(source) ? Readable.from([source]) : createReadStream(source);
  const chunks = [];
  for await (const chunk of input.pipe(zlib.createGzip({ level: HOSTING_GZIP_LEVEL }))) chunks.push(chunk);
  return sha256(Buffer.concat(chunks));
}

// The Hosting hash of every frozen file, keyed by manifest path, after the
// frozen copy has been re-verified against its manifest.
export async function expectedHostingHashes(root, manifestSha256, { repoRoot = ROOT } = {}) {
  const manifest = await verifyFrozen(root, manifestSha256, { repoRoot });
  const hashes = new Map();
  for (const file of manifest.files) hashes.set(file.path, await hostingFileHash(path.join(root, RELEASE_PUBLIC, file.path)));
  // Re-verify: the bytes hashed above are still the manifest's bytes.
  await verifyFrozen(root, manifestSha256, { repoRoot });
  return { manifest, hashes };
}

// R1: `firebase deploy --json` reports the version it created and released
// (lib/deploy/index.js: { hosting: <version name> } for one deploy). Exactly
// one version, on this site, or the run stops.
export function parseDeployVersion(text, site) {
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    throw new Error('firebase deploy --json output was not JSON');
  }
  const version = data?.result?.hosting;
  if (data?.status !== 'success' || typeof version !== 'string') throw new Error('firebase deploy did not report exactly one Hosting version');
  const match = version.match(/^sites\/([a-z0-9-]{1,63})\/versions\/([A-Za-z0-9_-]{1,128})$/);
  if (!match || match[1] !== site) throw new Error('firebase deploy reported a version on another site');
  return version;
}

// R2: a release record binds one Hosting version to the exact bytes it serves:
// for every shell file, its size and SHA-256 and its Hosting (gzip) hash. A
// verified deploy prints its record and the record's SHA-256; once that digest
// is independently approved, the record is the only acceptable rollback
// baseline for the next shell update. Canonical JSON plus one newline.
const VERSION_NAME = /^sites\/([a-z0-9-]{1,63})\/versions\/([A-Za-z0-9_-]{1,128})$/;

export function canonicalReleaseRecord({ site, versionName, files }) {
  return `${JSON.stringify({
    version: 1,
    site,
    versionName,
    files: files.map(({ path: p, size, sha256: digest, hostingHash }) => ({ path: p, size, sha256: digest, hostingHash })),
  })}\n`;
}

export async function releaseRecord({ root, manifestSha256, versionName, site, repoRoot = ROOT }) {
  const match = String(versionName).match(VERSION_NAME);
  if (!match || match[1] !== site) throw new Error('Release record version is not on this site');
  const { manifest, hashes } = await expectedHostingHashes(root, manifestSha256, { repoRoot });
  return canonicalReleaseRecord({
    site,
    versionName,
    files: manifest.files.map((file) => ({ ...file, hostingHash: hashes.get(file.path) })),
  });
}

export function parseReleaseRecord(text, expectedSha256, site) {
  if (!DIGEST.test(expectedSha256 || '')) throw new Error('Approved baseline record digest is missing or malformed');
  if (sha256(Buffer.from(String(text), 'utf8')) !== expectedSha256) throw new Error('Baseline record does not match its approved digest');
  let record;
  try {
    record = JSON.parse(text);
  } catch {
    throw new Error('Baseline record is not JSON');
  }
  if (record?.version !== 1 || record.site !== site || !Array.isArray(record.files)) throw new Error('Baseline record is not for this site');
  const match = String(record.versionName).match(VERSION_NAME);
  if (!match || match[1] !== site) throw new Error('Baseline record version is not on this site');
  if (canonicalReleaseRecord(record) !== text) throw new Error('Baseline record is not canonical');
  if (JSON.stringify(record.files.map((f) => f.path)) !== JSON.stringify(SECURE_SHELL_FILES)) throw new Error('Baseline record is not the secure shell file list');
  for (const file of record.files) {
    if (!Number.isInteger(file.size) || file.size < 1 || file.size > MAX_FILE_BYTES || !DIGEST.test(file.sha256) || !DIGEST.test(file.hostingHash)) {
      throw new Error(`Baseline record entry is malformed: ${file.path}`);
    }
  }
  return record;
}

async function readRecord(file, expectedSha256, site) {
  return parseReleaseRecord((await readRegular(file)).toString('utf8'), expectedSha256, site);
}

// Every byte the live baseline serves must be the approved record's (the
// header/CSP/script checks in verifyBaselineShell still run as well).
export async function verifyBaselineBytes({ record, fetchDir }) {
  for (const [index, file] of record.files.entries()) {
    const body = await fs.readFile(path.join(fetchDir, `${index}.body`));
    if (body.length !== file.size || sha256(body) !== file.sha256) throw new Error(`Live baseline ${file.path} is not the approved baseline`);
  }
  const index = record.files.find((file) => file.path === 'index.html');
  const root = await fs.readFile(path.join(fetchDir, 'root.body'));
  if (root.length !== index.size || sha256(root) !== index.sha256) throw new Error('Live baseline / is not the approved baseline');
  return true;
}

// GET sites/{site}/versions/{id}/files. One page is all a shell release can have;
// a continuation token, a duplicate, an unfinished upload or any path outside
// the expected list fails. With expectedHashes (path -> Hosting hash) every
// file's content hash must match too (R1).
export function assertVersionFiles(text, expectedPaths, expectedHashes = null) {
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    throw new Error('Hosting version file list was not JSON');
  }
  if (!data || typeof data !== 'object' || Array.isArray(data) || !Array.isArray(data.files)) {
    throw new Error('Hosting version file list has no files array');
  }
  if (data.nextPageToken) throw new Error('Hosting version file list is paged; refusing a partial view');
  const seen = new Set();
  for (const file of data.files) {
    const p = typeof file?.path === 'string' ? file.path : '';
    if (!p.startsWith('/') || p.includes('..') || p.includes('\\')) throw new Error('Hosting version file has an invalid path');
    if (file.status !== 'ACTIVE') throw new Error(`Hosting version file is not ACTIVE: ${p}`);
    if (!DIGEST.test(file.hash || '')) throw new Error(`Hosting version file has no content hash: ${p}`);
    if (seen.has(p)) throw new Error(`Hosting version lists ${p} twice`);
    seen.add(p);
  }
  const actual = [...seen].map((p) => p.slice(1)).sort();
  const wanted = [...expectedPaths].sort();
  const extra = actual.filter((p) => !wanted.includes(p));
  const missing = wanted.filter((p) => !actual.includes(p));
  if (extra.length) throw new Error(`Hosting version serves files outside the approved list: ${extra.join(', ')}`);
  if (missing.length) throw new Error(`Hosting version is missing approved files: ${missing.join(', ')}`);
  if (expectedHashes) {
    for (const file of data.files) {
      const rel = file.path.slice(1);
      if (expectedHashes.get(rel) !== file.hash) throw new Error(`Hosting version content differs from the approved release: ${rel}`);
    }
  }
  return actual;
}

// The exact response headers firebase.secure-blitz.json approves for every path.
export function approvedHeaders(config) {
  const block = config?.hosting?.headers;
  if (!Array.isArray(block) || block.length !== 1 || block[0]?.source !== '**') throw new Error('Approved Hosting headers must be one ** block');
  const map = new Map();
  for (const { key, value } of block[0].headers) {
    const name = String(key).toLowerCase();
    if (map.has(name)) throw new Error(`Approved Hosting headers repeat ${name}`);
    map.set(name, String(value));
  }
  if (map.get('content-security-policy') !== productionCsp()) throw new Error('Approved CSP header is not the production policy');
  if (map.get('x-frame-options') !== 'DENY') throw new Error('Approved headers must deny framing');
  return map;
}

// curl -D output for one request. Exactly one response: no redirect hop, no interim.
export function parseHeaderDump(text) {
  const blocks = String(text).replace(/\r/g, '').split('\n\n').map((part) => part.trim()).filter(Boolean);
  if (blocks.length !== 1) throw new Error('Expected exactly one HTTP response (no redirects)');
  const [statusLine, ...lines] = blocks[0].split('\n');
  const match = statusLine.match(/^HTTP\/[0-9.]+\s+(\d{3})(?:\s.*)?$/);
  if (!match) throw new Error('Malformed HTTP status line');
  const headers = new Map();
  for (const line of lines) {
    const idx = line.indexOf(':');
    if (idx <= 0) throw new Error('Malformed HTTP header line');
    const name = line.slice(0, idx).trim().toLowerCase();
    const value = line.slice(idx + 1).trim();
    if (!headers.has(name)) headers.set(name, []);
    headers.get(name).push(value);
  }
  return { status: Number(match[1]), headers };
}

const CONTENT_TYPES = {
  '.html': /^text\/html\b/i,
  '.js': /^(?:text|application)\/javascript\b/i,
  '.css': /^text\/css\b/i,
};

export function assertResponseHeaders(dumpText, rel, approved) {
  const { status, headers } = parseHeaderDump(dumpText);
  if (status !== 200) throw new Error(`${rel} returned HTTP ${status}, not 200`);
  if (headers.has('location')) throw new Error(`${rel} carries a redirect Location header`);
  for (const [name, value] of approved) {
    const got = headers.get(name) || [];
    if (got.length !== 1) throw new Error(`${rel} must send exactly one ${name} header (got ${got.length})`);
    if (got[0] !== value) throw new Error(`${rel} ${name} header is not the approved value`);
  }
  // Exact equality with the approved CSP above already rejects any weakened
  // script-src, unsafe-inline/eval or missing frame-ancestors. A second,
  // report-only policy is refused so it cannot be mistaken for enforcement.
  if (headers.has('content-security-policy-report-only')) throw new Error(`${rel} sends a report-only CSP`);
  const ext = path.posix.extname(rel === '/' ? 'index.html' : rel);
  const type = (headers.get('content-type') || [])[0] || '';
  if (CONTENT_TYPES[ext] && !CONTENT_TYPES[ext].test(type)) throw new Error(`${rel} has an unexpected content type`);
  return true;
}

// The shell page itself: the exact production CSP in its meta tag, the two
// approved external scripts and nothing else that can run.
export function assertShellHtml(html) {
  if (typeof html !== 'string' || !html.length) throw new Error('Shell page is empty');
  const metas = [...html.matchAll(/<meta\s+http-equiv="Content-Security-Policy"\s+content="([^"]*)"\s*>/gi)];
  if (metas.length !== 1 || metas[0][1] !== productionCsp()) throw new Error('Shell page CSP is not the exact production policy');
  const scripts = [...html.matchAll(/<script\b[^>]*>/gi)].map((m) => m[0]);
  const wanted = ['<script src="config.js" defer>', '<script src="shell.js" defer>'];
  if (JSON.stringify(scripts) !== JSON.stringify(wanted)) throw new Error('Shell page loads scripts other than config.js and shell.js');
  if ([...html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/gi)].some((m) => m[1].trim())) throw new Error('Shell page has inline script');
  if (/\son[a-z]+\s*=|javascript:|<iframe|<object|<embed|<base\b|http-equiv="refresh"/i.test(html)) {
    throw new Error('Shell page has inline handlers, frames, a base URL or a refresh');
  }
  if (!html.includes('id="unlock-form"')) throw new Error('Live page is not the secure shell');
  if (/data\.enc\.json|src="app\.js"/.test(html)) throw new Error('Shell page references the public demo');
  return true;
}

// The fetch directory holds, for each index i in manifest order, i.headers and
// i.body; plus root.headers/root.body for "/". Every byte must equal the manifest.
export async function verifyLive({ root, manifestSha256, fetchDir, repoRoot = ROOT }) {
  const manifest = await verifyFrozen(root, manifestSha256, { repoRoot });
  const approved = approvedHeaders(JSON.parse(await fs.readFile(path.join(repoRoot, 'firebase.secure-blitz.json'), 'utf8')));
  const byPath = new Map(manifest.files.map((file) => [file.path, file]));
  const check = async (label, rel, file) => {
    const dump = await fs.readFile(path.join(fetchDir, `${label}.headers`), 'utf8');
    assertResponseHeaders(dump, rel, approved);
    const body = await fs.readFile(path.join(fetchDir, `${label}.body`));
    if (body.length !== file.size || sha256(body) !== file.sha256) throw new Error(`Live ${rel} is not byte-identical to the frozen release`);
    return body;
  };
  for (const [index, file] of manifest.files.entries()) await check(String(index), file.path, file);
  const page = await check('root', '/', byPath.get('index.html'));
  assertShellHtml(page.toString('utf8'));
  return manifest;
}

// A live shell whose bytes we cannot compare (the rollback baseline of an
// update): every allowlisted path must answer 200 with the exact approved
// headers, "/" must equal /index.html, the page must be the strict shell, and
// config.js must be the production web config.
export async function verifyBaselineShell({ fetchDir, repoRoot = ROOT }) {
  const approved = approvedHeaders(JSON.parse(await fs.readFile(path.join(repoRoot, 'firebase.secure-blitz.json'), 'utf8')));
  for (const [index, rel] of SECURE_SHELL_FILES.entries()) {
    assertResponseHeaders(await fs.readFile(path.join(fetchDir, `${index}.headers`), 'utf8'), rel, approved);
  }
  assertResponseHeaders(await fs.readFile(path.join(fetchDir, 'root.headers'), 'utf8'), '/', approved);
  const html = await fs.readFile(path.join(fetchDir, 'root.body'), 'utf8');
  const indexHtml = await fs.readFile(path.join(fetchDir, `${SECURE_SHELL_FILES.indexOf('index.html')}.body`), 'utf8');
  if (html !== indexHtml) throw new Error('Live / and /index.html differ');
  assertShellHtml(html);
  assertPrivateWebConfig(await fs.readFile(path.join(fetchDir, `${SECURE_SHELL_FILES.indexOf('config.js')}.body`), 'utf8'));
  const shell = await fs.readFile(path.join(fetchDir, `${SECURE_SHELL_FILES.indexOf('shell.js')}.body`), 'utf8');
  if (/data\.enc\.json/.test(shell)) throw new Error('Live shell script references public ciphertext');
  return true;
}

async function main(argv) {
  const [mode, ...rest] = argv;
  if (mode === '--freeze') {
    const { root, manifestSha256 } = await freezeRelease({ source: rest[0] });
    process.stdout.write(`${root}\n${manifestSha256}\n`);
  } else if (mode === '--verify-frozen') {
    await verifyFrozen(rest[0], rest[1]);
    console.log('PASS: frozen release matches its manifest');
  } else if (mode === '--paths') {
    const manifest = await verifyFrozen(rest[0], rest[1]);
    for (const file of manifest.files) console.log(file.path);
  } else if (mode === '--version-files') {
    // R1: paths and every content hash, in the CLI's gzip representation.
    const { manifest, hashes } = await expectedHostingHashes(rest[0], rest[1]);
    assertVersionFiles(readFileSync(0, 'utf8'), manifest.files.map((file) => file.path), hashes);
    console.log('PASS: live version serves exactly the frozen files, byte for byte');
  } else if (mode === '--release-record') {
    // <root> <manifest sha> <version name> <site>: prints the record, then its SHA-256.
    const text = await releaseRecord({ root: rest[0], manifestSha256: rest[1], versionName: rest[2], site: rest[3] });
    process.stdout.write(`${text.trimEnd()}\n${sha256(Buffer.from(text, 'utf8'))}\n`);
  } else if (mode === '--check-baseline-record') {
    // <record file> <approved sha> <site> [<live version name>]
    const record = await readRecord(rest[0], rest[1], rest[2]);
    if (rest[3] !== undefined && record.versionName !== rest[3]) throw new Error('The live version is not the approved baseline version');
    console.log('PASS: approved baseline record');
  } else if (mode === '--version-files-record') {
    // R2: the rollback version must list the approved record's files and content hashes.
    const record = await readRecord(rest[0], rest[1], rest[2]);
    const hashes = new Map(record.files.map((file) => [file.path, file.hostingHash]));
    assertVersionFiles(readFileSync(0, 'utf8'), record.files.map((file) => file.path), hashes);
    console.log('PASS: rollback version serves exactly the approved baseline');
  } else if (mode === '--verify-baseline-bytes') {
    await verifyBaselineBytes({ record: await readRecord(rest[0], rest[1], rest[2]), fetchDir: rest[3] });
    console.log('PASS: live baseline bytes are the approved baseline');
  } else if (mode === '--deploy-version') {
    process.stdout.write(`${parseDeployVersion(readFileSync(0, 'utf8'), rest[0])}\n`);
  } else if (mode === '--version-files-demo') {
    // The rollback target for the demo baseline must be exactly the fictional demo build.
    assertVersionFiles(readFileSync(0, 'utf8'), DEMO_HOSTING_FILES);
    console.log('PASS: rollback version serves exactly the fictional demo file list');
  } else if (mode === '--version-files-shell') {
    // The rollback target for the shell baseline must be exactly a secure shell build.
    assertVersionFiles(readFileSync(0, 'utf8'), SECURE_SHELL_FILES);
    console.log('PASS: rollback version serves exactly the secure shell file list');
  } else if (mode === '--shell-paths') {
    for (const rel of SECURE_SHELL_FILES) console.log(rel);
  } else if (mode === '--verify-baseline-shell') {
    await verifyBaselineShell({ fetchDir: rest[0] });
    console.log('PASS: live baseline is an exact production secure shell');
  } else if (mode === '--verify-live') {
    await verifyLive({ root: rest[0], manifestSha256: rest[1], fetchDir: rest[2] });
    console.log('PASS: live files, status codes and security headers match the frozen release');
  } else if (mode === '--remove') {
    await removeRelease(rest[0]);
  } else {
    throw new Error('Use --freeze, --verify-frozen, --paths, --shell-paths, --version-files, --deploy-version, --release-record, --check-baseline-record, --version-files-record, --verify-baseline-bytes, --version-files-demo, --version-files-shell, --verify-live, --verify-baseline-shell or --remove');
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch((error) => {
    console.error(`STOP: ${error.message}`);
    process.exitCode = 1;
  });
}
