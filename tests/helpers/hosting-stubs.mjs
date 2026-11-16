// Runs the real scripts/deploy-secure-blitz.sh from a temporary repository copy
// with every cloud tool (firebase, gcloud, curl), git and npm replaced by stubs
// on PATH. Nothing here can reach Firebase, Google Cloud or the network.
//
// The firebase stub "deploys" by copying the public directory named in the
// --config file it is given, so the test sees exactly what the script would
// have uploaded. The curl stub serves that copy with the approved Hosting
// headers and answers the two Hosting API reads the script makes.
//
// Modes (all fictional data):
//   ok                    nothing interferes
//   export-in-build-dir   after the build is checked, a fictional plaintext export
//                         appears in .firebase-blitz-private-shell under odd names
//   tamper-before-deploy  after the build is checked and before deploy, shell.js
//                         changes in the build dir and in any frozen release root
//   tamper-during-deploy  while the CLI is uploading, a fictional plaintext export
//                         is added to the directory being deployed
//   version-extra         the new Hosting version lists a file nobody built
//   rollback-extra        the version being replaced lists an extra file
//   weak-csp | no-xfo | report-only | dup-csp | redirect | cdn-mismatch | missing-404
//                         the live site differs from the approved release after deploy
//   baseline-<mode>       (shell baseline only) the same faults on the live baseline
//   live-is-demo          shell baseline requested, but the fictional demo is live
//   cipher-live           shell baseline, but /data.enc.json is still served
//   wrong-release         the operator-supplied release is not the live one
//   demo-baseline-shell-live  demo baseline requested while a shell is live
//   live-not-deployed     R1: after the deploy the channel serves another version
//                         with the same files (a concurrent deploy), not ours
//   version-hash-stale    R1: the new version lists the right paths but one file's
//                         content hash is not the frozen file's
//   drift-after-verify    R1: the channel changes once the release has been checked
//   baseline-arbitrary-js R2: the live shell (and its version) serve a shell.js that
//                         passes every structural check but is not the approved one
//   baseline-version-hash R2: the rollback version's Hosting hash for shell.js is not
//                         the approved record's, although the served bytes are
//   baseline-record-other-version  R2: the approved record names another version
// Shell-baseline runs get an approved release record of the pre-deploy shell
// (BLITZ_APPROVED_BASELINE_RECORD[_SHA256]) unless record: false.
// Version file hashes are the CLI's representation: SHA-256 of gzip level 9.
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { appendFile, chmod, cp, mkdir, mkdtemp, readdir, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { gzipSync } from 'node:zlib';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
export const site = 'master-intelligence-5496f-lb';
export const project = 'master-intelligence-5496f';
export const approved = '2222222222222222222222222222222222222222';
export const releaseBefore = `sites/${site}/channels/live/releases/1794426642121000`;
export const releaseAfter = `sites/${site}/channels/live/releases/1794999999999000`;
export const versionBefore = 'beforeversion01';
export const versionAfter = 'afterversion002';
export const releaseOther = `sites/${site}/channels/live/releases/1794999999999555`;
export const versionOther = 'otherversion03';
export const FICTIONAL_EXPORT = '{"contacts":[{"contact":"Example Plaintext Export","account":"EXAMPLE Leak Co"}]}\n';

export function webConfig(apiKey = 'AIzaSyDUMMYPUBLICWEBCONFIGKEY000000000') {
  return {
    firebase: {
      apiKey,
      authDomain: `${project}.firebaseapp.com`,
      projectId: project,
      appId: '1:000000000000:web:abcdef0123456789',
    },
    useEmulators: false,
  };
}

export function cleanEnv(overrides = {}) {
  const env = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (typeof value !== 'string') continue;
    if (key.startsWith('BLITZ_') || /PASSPHRASE/i.test(key)) continue;
    if (['CI', 'GITHUB_ACTIONS', 'FIREBASE_TOKEN'].includes(key) || /^google_application_credentials$/i.test(key)) continue;
    env[key] = value;
  }
  return { ...env, ...overrides };
}

async function exe(file, body) {
  await writeFile(file, body, { mode: 0o755 });
  await chmod(file, 0o755);
}

export async function listFiles(dir, rel = '') {
  let entries = [];
  try {
    entries = await readdir(path.join(dir, rel), { withFileTypes: true });
  } catch {
    return [];
  }
  const out = [];
  for (const entry of entries) {
    const child = path.posix.join(rel, entry.name);
    if (entry.isDirectory()) out.push(...await listFiles(dir, child));
    else out.push(child);
  }
  return out.sort();
}

const FIREBASE_STUB = `
const fs = require('node:fs');
const path = require('node:path');
const args = process.argv.slice(2);
const env = process.env;
fs.appendFileSync(env.STUB_FIREBASE_LOG, args.join(' ') + '\\n');
if (args.includes('hosting:sites:list')) { process.stdout.write(fs.readFileSync(env.STUB_SITES, 'utf8')); process.exit(0); }
if (args[0] !== 'deploy') { process.stderr.write('unexpected firebase: ' + args.join(' ') + '\\n'); process.exit(1); }
const configFile = path.resolve(process.cwd(), args[args.indexOf('--config') + 1]);
const config = JSON.parse(fs.readFileSync(configFile, 'utf8'));
const pub = path.resolve(path.dirname(configFile), config.hosting.public);
if (env.STUB_MODE === 'tamper-during-deploy') {
  fs.chmodSync(pub, 0o700);
  fs.writeFileSync(path.join(pub, 'campaign-export.json'), env.STUB_EXPORT);
}
const out = path.join(env.STUB_STATE, 'live-files');
function copy(from, to) {
  fs.mkdirSync(to, { recursive: true });
  for (const entry of fs.readdirSync(from, { withFileTypes: true })) {
    if (entry.name.startsWith('.')) continue; // firebase.json ignore: **/.*
    const a = path.join(from, entry.name); const b = path.join(to, entry.name);
    if (entry.isDirectory()) copy(a, b); else fs.writeFileSync(b, fs.readFileSync(a));
  }
}
copy(pub, out);
fs.writeFileSync(path.join(env.STUB_STATE, 'deployed-config'), configFile);
fs.appendFileSync(env.STUB_FIREBASE_LOG, 'DEPLOY\\n');
fs.writeFileSync(path.join(env.STUB_STATE, 'deployed'), '', { flag: 'a' });
if (args.includes('--json')) process.stdout.write(JSON.stringify({ status: 'success', result: { hosting: 'sites/${site}/versions/${versionAfter}' } }, null, 2) + '\\n');
`;

const GCLOUD_STUB = `
const fs = require('node:fs');
const path = require('node:path');
const args = process.argv.slice(2).join(' ');
const env = process.env;
if (args.includes('print-access-token')) { process.stdout.write('ya29.synthetic-hosting-release-token-for-tests\\n'); process.exit(0); }
const deployedFlag = path.join(env.STUB_STATE, 'deployed');
const once = path.join(env.STUB_STATE, 'interfered');
const deployed = fs.existsSync(deployedFlag);
const build = path.join(process.cwd(), '.firebase-blitz-private-shell');
if (!deployed && !fs.existsSync(once) && fs.existsSync(build)) {
  if (env.STUB_MODE === 'export-in-build-dir') {
    fs.writeFileSync(path.join(build, 'contacts-export.json'), env.STUB_EXPORT);
    fs.mkdirSync(path.join(build, 'img', 'cache'), { recursive: true });
    fs.writeFileSync(path.join(build, 'img', 'cache', 'logo.png.json'), env.STUB_EXPORT);
    fs.writeFileSync(once, '');
  } else if (env.STUB_MODE === 'tamper-before-deploy') {
    fs.appendFileSync(path.join(build, 'shell.js'), '\\n// tampered after review\\n');
    for (const name of fs.readdirSync(env.TMPDIR)) {
      if (!name.startsWith('blitz-release-')) continue;
      const pub = path.join(env.TMPDIR, name, 'public');
      fs.chmodSync(pub, 0o700);
      fs.chmodSync(path.join(pub, 'shell.js'), 0o600);
      fs.appendFileSync(path.join(pub, 'shell.js'), '\\n// tampered after freeze\\n');
    }
    fs.writeFileSync(once, '');
  }
}
process.stdout.write('False\\n');
`;

const NPM_STUB = `#!/bin/sh
printf '%s\\n' "$*" >> "$STUB_NPM_LOG"
for name in BLITZ_APPROVE_SECURE_SHELL_DEPLOY BLITZ_APPROVED_COMMIT BLITZ_EXPECTED_DEMO_RELEASE BLITZ_EXPECTED_LIVE_RELEASE BLITZ_RELEASE_BASELINE BLITZ_APPROVED_BASELINE_RECORD BLITZ_APPROVED_BASELINE_RECORD_SHA256; do
  if env | grep -q "^$name="; then printf '%s\\n' "APPROVAL_VAR_PRESENT $name" >> "$STUB_NPM_LOG"; fi
done
if [ "$1" = run ] && [ "$2" = test:secure ]; then
  printf '%s\\n' "nonce=$BLITZ_SECURE_ATTEST_NONCE" tests=7 pass=7 fail=0 cancelled=0 skipped=0 todo=0 iphone=pass > "$BLITZ_SECURE_ATTEST_PATH"
fi
exit 0
`;

const GIT_STUB = `#!/bin/sh
case "$1" in
  rev-parse) printf '%s\\n' "$BLITZ_APPROVED_COMMIT" ;;
  status) ;;
  *) echo "unexpected git: $*" >&2; exit 1 ;;
esac
`;

const CURL_STUB = `
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const args = process.argv.slice(2);
const env = process.env;
let out = null; let dump = null; let writeOut = null; let fail = false; const headers = []; let url = null;
for (let i = 0; i < args.length; i++) {
  const a = args[i];
  if (a === '-o' || a === '--output') out = args[++i];
  else if (a === '-D' || a === '--dump-header') dump = args[++i];
  else if (a === '--write-out' || a === '-w') writeOut = args[++i];
  else if (a === '-H') headers.push(args[++i]);
  else if (a === '--max-time' || a === '--retry') i++;
  else if (a === '--fail') fail = true;
  else if (a === '-L' || a === '--location') { process.stderr.write('redirects not allowed'); process.exit(2); }
  else if (/^https:\\/\\//.test(a)) url = a;
}
fs.appendFileSync(env.STUB_CURL_LOG, url + '\\n');
const flag = path.join(env.STUB_STATE, 'deployed');
const deployed = fs.existsSync(flag);
const mode = env.STUB_MODE;
const baseline = env.STUB_BASELINE;
const SITE = '${site}';
const origin = 'https://' + SITE + '.web.app';
const api = 'https://firebasehosting.googleapis.com/v1beta1/sites/' + SITE;
const approved = JSON.parse(fs.readFileSync(env.STUB_APPROVED_CONFIG, 'utf8')).hosting.headers[0].headers;
let status = 404; let body = Buffer.alloc(0); let extra = [];
function authed() {
  const auth = headers.find((h) => h.startsWith('@'));
  return auth && /^Authorization: Bearer ya29\\./.test(fs.readFileSync(auth.slice(1), 'utf8'));
}
function list(dir, rel) {
  let names = [];
  try { names = fs.readdirSync(path.join(dir, rel), { withFileTypes: true }); } catch { return []; }
  const outList = [];
  for (const e of names) {
    const child = rel ? rel + '/' + e.name : e.name;
    if (e.isDirectory()) outList.push(...list(dir, child)); else outList.push(child);
  }
  return outList;
}
const SHELL = JSON.parse(env.STUB_SHELL_FILES);
const DEMO = JSON.parse(env.STUB_DEMO_FILES);
const zlib = require('node:zlib');
// The Hosting API's hash: SHA-256 of the CLI's gzip (level 9) of the file.
function hostingHash(buf) { return crypto.createHash('sha256').update(zlib.gzipSync(buf, { level: 9 })).digest('hex'); }
function versionEntry(p, dir, tweak) {
  const file = dir ? path.join(dir, p) : null;
  let buf = file && fs.existsSync(file) ? fs.readFileSync(file) : Buffer.from('missing:' + p);
  if (tweak && tweak(p)) buf = Buffer.concat([buf, Buffer.from('\\n// stale upload\\n')]);
  return { path: '/' + p, hash: hostingHash(buf), status: 'ACTIVE' };
}
let postReads = 0;
if (deployed && url === api + '/channels/live') {
  const counter = path.join(env.STUB_STATE, 'post-deploy-channel-reads');
  postReads = (fs.existsSync(counter) ? Number(fs.readFileSync(counter, 'utf8')) : 0) + 1;
  fs.writeFileSync(counter, String(postReads));
}
if (url === api + '/channels/live') {
  if (!authed()) status = 401;
  else {
    status = 200;
    let release = deployed ? '${releaseAfter}' : '${releaseBefore}';
    let version = deployed ? '${versionAfter}' : '${versionBefore}';
    if (deployed && (mode === 'live-not-deployed' || (mode === 'drift-after-verify' && postReads >= 2))) {
      release = '${releaseOther}';
      version = '${versionOther}';
    }
    body = Buffer.from(JSON.stringify({ name: 'sites/' + SITE + '/channels/live', url: origin, release: { name: release, type: 'DEPLOY', version: { name: 'sites/' + SITE + '/versions/' + version, status: 'FINALIZED' } } }));
  }
} else if (url === api + '/versions/${versionBefore}/files') {
  if (!authed()) status = 401;
  else {
    status = 200;
    const names = [...(baseline === 'shell' ? SHELL : DEMO)];
    if (mode === 'rollback-extra') names.push('campaign-export.json');
    const dir = baseline === 'shell' ? env.STUB_PRE_DIR : env.STUB_DEMO_DIR;
    const stale = mode === 'baseline-version-hash' ? (n) => n === 'shell.js' : null;
    body = Buffer.from(JSON.stringify({ files: names.map((n) => versionEntry(n, dir, stale)) }));
  }
} else if (url === api + '/versions/${versionAfter}/files' || url === api + '/versions/${versionOther}/files') {
  if (!authed() || !deployed) status = 401;
  else {
    status = 200;
    const live = path.join(env.STUB_STATE, 'live-files');
    const names = list(live, '');
    if (mode === 'version-extra') names.push('campaign-export.json');
    const stale = mode === 'version-hash-stale' ? (n) => n === 'shell.js' : null;
    body = Buffer.from(JSON.stringify({ files: names.map((n) => versionEntry(n, live, stale)) }));
  }
} else if (url && url.startsWith(origin + '/')) {
  const name = url === origin + '/' ? 'index.html' : decodeURIComponent(url.slice(origin.length + 1));
  const demoLive = !deployed && (baseline === 'demo' || mode === 'live-is-demo');
  const dir = deployed ? path.join(env.STUB_STATE, 'live-files') : (demoLive ? env.STUB_DEMO_DIR : env.STUB_PRE_DIR);
  const fault = deployed ? mode : (mode.startsWith('baseline-') ? mode.slice('baseline-'.length) : '');
  const file = path.join(dir, name);
  if (!name.includes('..') && fs.existsSync(file) && fs.statSync(file).isFile()) {
    status = 200;
    body = fs.readFileSync(file);
  } else if (name === 'data.enc.json' && !deployed && mode === 'cipher-live') {
    status = 200; body = fs.readFileSync(env.STUB_DEMO_CIPHER);
  }
  if (status === 200 && !demoLive) {
    for (const h of approved) extra.push([h.key.toLowerCase(), h.value]);
    if (fault === 'weak-csp') extra = extra.map(([k, v]) => k === 'content-security-policy' ? [k, v.replace("script-src 'self'", "script-src 'self' 'unsafe-inline'")] : [k, v]);
    if (fault === 'no-xfo') extra = extra.filter(([k]) => k !== 'x-frame-options');
    if (fault === 'report-only') extra.push(['content-security-policy-report-only', "default-src *"]);
    if (fault === 'dup-csp') extra.push(['content-security-policy', "default-src *"]);
    if (fault === 'redirect' && name === 'shell.js') { status = 301; body = Buffer.alloc(0); extra = [['location', 'https://attacker.example/shell.js']]; }
    if (fault === 'cdn-mismatch' && name === 'blitz.css') body = Buffer.concat([body, Buffer.from('/* edge copy */')]);
    if (fault === 'missing-404' && name === 'fonts/Manrope-latin.woff2') { status = 404; body = Buffer.alloc(0); extra = []; }
    if (fault === 'extra-script' && name === 'index.html') body = Buffer.from(body.toString('utf8').replace('</body>', '<script src="analytics.js" defer></script></body>'));
  }
  const ext = path.extname(name);
  const types = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.json': 'application/json', '.png': 'image/png', '.webp': 'image/webp', '.woff2': 'font/woff2', '.ico': 'image/x-icon' };
  if (status === 200) extra.unshift(['content-type', types[ext] || 'application/octet-stream']);
}
if (fail && status >= 400) { process.stderr.write('curl: (22) The requested URL returned error: ' + status + '\\n'); process.exit(22); }
if (dump) fs.writeFileSync(dump, 'HTTP/2 ' + status + '\\r\\n' + extra.map(([k, v]) => k + ': ' + v + '\\r\\n').join('') + '\\r\\n');
if (out && out !== '/dev/null') fs.writeFileSync(out, body);
else if (!out) process.stdout.write(body);
if (writeOut === '%{http_code}') process.stdout.write(String(status));
`;

// Copies the repository pieces the script needs. For the demo baseline the copy's
// DEMO_SHA is pointed at a synthetic demo ciphertext; the real value pins a
// historical build whose bytes are not reproducible.
// R2: the approved record of a shell directory served as `versionName`, built
// independently of scripts/secure-release.mjs (same canonical form).
export async function shellRecord(dir, versionName, files) {
  const sha = (b) => createHash('sha256').update(b).digest('hex');
  const entries = [];
  for (const rel of files) {
    const bytes = await readFile(path.join(dir, rel));
    entries.push({ path: rel, size: bytes.length, sha256: sha(bytes), hostingHash: sha(gzipSync(bytes, { level: 9 })) });
  }
  const text = `${JSON.stringify({ version: 1, site, versionName, files: entries })}\n`;
  return { text, sha256: sha(Buffer.from(text, 'utf8')) };
}

export async function runDeploy({ mode = 'ok', baseline = 'demo', buildShell, record = true } = {}) {
  const work = await mkdtemp(path.join(os.tmpdir(), 'blitz-release-harness-'));
  const repo = path.join(work, 'repo');
  const bin = path.join(work, 'bin');
  const state = path.join(work, 'state');
  const tmp = path.join(work, 'tmp');
  try {
    for (const dir of [repo, bin, state, tmp]) await mkdir(dir);
    for (const entry of ['scripts', 'secure', 'docs']) await cp(path.join(root, entry), path.join(repo, entry), { recursive: true });
    for (const file of ['firebase.secure-blitz.json', '.firebaserc', 'package.json']) await cp(path.join(root, file), path.join(repo, file));
    await symlink(path.join(root, 'node_modules'), path.join(repo, 'node_modules'), 'dir');
    const demoDir = path.join(work, 'demo');
    await mkdir(demoDir);
    const demoCipher = path.join(demoDir, 'data.enc.json');
    await writeFile(demoCipher, '{"synthetic":"fictional demo ciphertext for the release harness"}\n');
    await cp(path.join(root, 'docs', 'index.html'), path.join(demoDir, 'index.html'));
    if (baseline === 'demo') {
      const script = path.join(repo, 'scripts', 'deploy-secure-blitz.sh');
      const digest = createHash('sha256').update(await readFile(demoCipher)).digest('hex');
      const text = await readFile(script, 'utf8');
      await writeFile(script, text.replace(/^DEMO_SHA="[0-9a-f]{64}"$/m, `DEMO_SHA="${digest}"`));
    }
    const operatorConfig = path.join(work, 'secure-config.local.json');
    await writeFile(operatorConfig, JSON.stringify(webConfig()), { mode: 0o600 });
    // What is live before the deploy, independent of what the operator asked for.
    const preIsShell = baseline === 'shell' || mode === 'demo-baseline-shell-live';
    const preDir = preIsShell ? await buildShell(work, 'AIzaSyPREVIOUSLIVESHELLKEY0000000000000') : demoDir;
    let approvedRecord = null;
    if (preIsShell && baseline === 'shell' && record) {
      const { SECURE_SHELL_FILES: files } = await import('../../scripts/verify-secure-shell.mjs');
      const named = mode === 'baseline-record-other-version' ? 'approvedother01' : versionBefore;
      approvedRecord = await shellRecord(preDir, `sites/${site}/versions/${named}`, files);
      approvedRecord.file = path.join(work, 'approved-baseline-record.json');
      await writeFile(approvedRecord.file, approvedRecord.text);
      // After approval, the live shell.js is replaced by one that passes every
      // structural check (no ciphertext reference, same page and config).
      if (mode === 'baseline-arbitrary-js') await appendFile(path.join(preDir, 'shell.js'), '\n;globalThis.__unapproved = 1;\n');
    }
    const sites = path.join(work, 'sites.json');
    await writeFile(sites, JSON.stringify({
      status: 'success',
      result: { sites: [project, `${project}-app`, `${project}-prep`, site].map((id) => ({ name: `projects/${project}/sites/${id}` })) },
    }));
    const logs = { firebase: path.join(work, 'firebase.log'), npm: path.join(work, 'npm.log'), curl: path.join(work, 'curl.log') };
    for (const file of Object.values(logs)) await writeFile(file, '');
    await exe(path.join(bin, 'git'), GIT_STUB);
    await exe(path.join(bin, 'npm'), NPM_STUB);
    await exe(path.join(bin, 'firebase'), `#!${process.execPath}\n${FIREBASE_STUB}`);
    await exe(path.join(bin, 'gcloud'), `#!${process.execPath}\n${GCLOUD_STUB}`);
    await exe(path.join(bin, 'curl'), `#!${process.execPath}\n${CURL_STUB}`);
    const { SECURE_SHELL_FILES } = await import('../../scripts/verify-secure-shell.mjs');
    // Older reviewed heads do not export the demo list; their scripts never ask for it.
    const DEMO_HOSTING_FILES = (await import('../../scripts/build-firebase-demo.mjs')).DEMO_HOSTING_FILES ?? [];
    const env = cleanEnv({
      PATH: `${bin}:${process.env.PATH}`,
      BLITZ_APPROVE_SECURE_SHELL_DEPLOY: 'YES',
      BLITZ_APPROVED_COMMIT: approved,
      BLITZ_SECURE_CONFIG: operatorConfig,
      TMPDIR: tmp,
      STUB_MODE: mode,
      STUB_BASELINE: preIsShell && mode !== 'live-is-demo' ? 'shell' : 'demo',
      STUB_STATE: state,
      STUB_SITES: sites,
      STUB_FIREBASE_LOG: logs.firebase,
      STUB_NPM_LOG: logs.npm,
      STUB_CURL_LOG: logs.curl,
      STUB_PRE_DIR: preDir,
      STUB_DEMO_DIR: demoDir,
      STUB_DEMO_CIPHER: demoCipher,
      STUB_APPROVED_CONFIG: path.join(root, 'firebase.secure-blitz.json'),
      STUB_SHELL_FILES: JSON.stringify(SECURE_SHELL_FILES),
      STUB_DEMO_FILES: JSON.stringify(DEMO_HOSTING_FILES),
      STUB_EXPORT: FICTIONAL_EXPORT,
    });
    if (baseline === 'demo') {
      env.BLITZ_EXPECTED_DEMO_RELEASE = releaseBefore;
    } else {
      env.BLITZ_RELEASE_BASELINE = 'shell';
      env.BLITZ_EXPECTED_LIVE_RELEASE = mode === 'wrong-release' ? `sites/${site}/channels/live/releases/1` : releaseBefore;
      if (approvedRecord) {
        env.BLITZ_APPROVED_BASELINE_RECORD = approvedRecord.file;
        env.BLITZ_APPROVED_BASELINE_RECORD_SHA256 = approvedRecord.sha256;
      }
    }
    const result = spawnSync('bash', [path.join(repo, 'scripts', 'deploy-secure-blitz.sh')], {
      cwd: repo, encoding: 'utf8', timeout: 240000, env,
    });
    const read = (file) => readFile(file, 'utf8');
    const deployedConfig = await read(path.join(state, 'deployed-config')).catch(() => '');
    return {
      result,
      firebase: await read(logs.firebase),
      npm: await read(logs.npm),
      curl: await read(logs.curl),
      deployedFiles: await listFiles(path.join(state, 'live-files')),
      deployedConfig,
      tmpLeftovers: (await readdir(tmp, { withFileTypes: true })).filter((e) => e.isDirectory()).map((e) => e.name),
      tmp,
      repo,
    };
  } finally {
    // The frozen release is read-only; restore write permission before removal.
    spawnSync('chmod', ['-R', 'u+w', work]);
    await rm(work, { recursive: true, force: true });
  }
}

export function deployCount(text) {
  return text.split('\n').filter((line) => line === 'DEPLOY').length;
}
