// Shell -> shell Hosting update path for deploy-secure-blitz.sh.
// Every cloud command (firebase, gcloud, curl) and git are stubs on PATH. The
// script runs from a temporary copy of the repository, so it never shares the
// real .firebase-blitz-private-shell output with other test files.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmod, cp, mkdir, mkdtemp, readdir, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { assertLiveShell } from '../scripts/secure-hosting-guard.mjs';
import { buildSecureShell } from '../scripts/build-secure-shell.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const site = 'master-intelligence-5496f-lb';
const project = 'master-intelligence-5496f';
const approved = '2222222222222222222222222222222222222222';
const releaseBefore = `sites/${site}/channels/live/releases/1794426642121000`;
const releaseAfter = `sites/${site}/channels/live/releases/1794999999999000`;
const versionBefore = 'beforeversion01';
const versionAfter = 'afterversion002';

function webConfig(apiKey = 'AIzaSyDUMMYPUBLICWEBCONFIGKEY000000000') {
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

function cleanEnv(overrides = {}) {
  const env = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (typeof value !== 'string') continue;
    if (key.startsWith('BLITZ_') || /PASSPHRASE/i.test(key)) continue;
    if (['CI', 'GITHUB_ACTIONS', 'FIREBASE_TOKEN', 'GOOGLE_APPLICATION_CREDENTIALS'].includes(key)) continue;
    env[key] = value;
  }
  return { ...env, ...overrides };
}

async function exe(file, body) {
  await writeFile(file, body, { mode: 0o755 });
  await chmod(file, 0o755);
}

async function builtShell(dir, apiKey) {
  const configPath = path.join(dir, `config-${apiKey.slice(-6)}.json`);
  await writeFile(configPath, JSON.stringify(webConfig(apiKey)));
  const out = path.join(dir, `shell-${apiKey.slice(-6)}`);
  await buildSecureShell({ emulator: false, configPath, out });
  return out;
}

async function readShell(dir) {
  return {
    html: await readFile(path.join(dir, 'index.html'), 'utf8'),
    config: await readFile(path.join(dir, 'config.js'), 'utf8'),
    shell: await readFile(path.join(dir, 'shell.js'), 'utf8'),
  };
}

test('live shell guard accepts a production shell and rejects the demo, emulator, and stripped pages', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'blitz-live-shell-'));
  try {
    const live = await readShell(await builtShell(dir, 'AIzaSyDUMMYPUBLICWEBCONFIGKEY000000000'));
    assert.equal(assertLiveShell(live), true);
    const demoHtml = await readFile(path.join(root, 'docs', 'index.html'), 'utf8');
    assert.throws(() => assertLiveShell({ ...live, html: demoHtml }));
    assert.throws(() => assertLiveShell({ ...live, html: live.html.replace(/<meta http-equiv="Content-Security-Policy"[^>]*>/, '') }), /Content-Security-Policy/);
    assert.throws(() => assertLiveShell({ ...live, html: live.html.replace("frame-ancestors 'none'", "frame-ancestors *") }), /framing/);
    assert.throws(() => assertLiveShell({ ...live, html: live.html.replace('id="unlock-form"', 'id="x"') }), /not the secure shell/);
    assert.throws(() => assertLiveShell({ ...live, html: live.html.replace('</body>', '<script src="app.js"></script></body>') }), /public demo/);
    assert.throws(() => assertLiveShell({ ...live, html: `${live.html}<!-- data.enc.json -->` }), /public demo/);
    const emulatorConfig = live.config.replace('"useEmulators":false', '"useEmulators":true');
    assert.notEqual(emulatorConfig, live.config);
    assert.throws(() => assertLiveShell({ ...live, config: emulatorConfig }), /emulator/i);
    assert.throws(() => assertLiveShell({ ...live, config: live.config.replace(project, 'other-project') }));
    assert.throws(() => assertLiveShell({ ...live, shell: `${live.shell}\nfetch("data.enc.json")` }), /ciphertext/);
    assert.throws(() => assertLiveShell({ ...live, shell: '' }), /missing/);
    assert.throws(() => assertLiveShell({ ...live, html: 'x'.repeat(4 * 1024 * 1024 + 1) }), /oversized/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

// git is stubbed (approved HEAD, clean tree) so the release-name checks are reached;
// firebase/gcloud/curl are not on this PATH, so nothing past them can run.
async function refusalBin() {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'blitz-refusal-bin-'));
  await exe(path.join(dir, 'git'), `#!/bin/sh
case "$1" in
  rev-parse) printf '%s\\n' "$BLITZ_APPROVED_COMMIT" ;;
  status) ;;
  *) exit 1 ;;
esac
`);
  return dir;
}

function refuse(bin, overrides) {
  return spawnSync('bash', ['scripts/deploy-secure-blitz.sh'], {
    cwd: root, encoding: 'utf8', timeout: 10000,
    env: cleanEnv({ PATH: `${bin}:/usr/bin:/bin`, BLITZ_APPROVE_SECURE_SHELL_DEPLOY: 'YES', BLITZ_APPROVED_COMMIT: approved, ...overrides }),
  });
}

test('release baseline must be demo or shell and pairs with exactly one expected-release variable', async () => {
  const bin = await refusalBin();
  const cases = [
    [{ BLITZ_RELEASE_BASELINE: 'live' }, /must be demo or shell/],
    [{ BLITZ_RELEASE_BASELINE: 'SHELL', BLITZ_EXPECTED_LIVE_RELEASE: releaseBefore }, /must be demo or shell/],
    [{ BLITZ_RELEASE_BASELINE: 'shell' }, /exact expected live release name is required/],
    [{ BLITZ_RELEASE_BASELINE: 'shell', BLITZ_EXPECTED_LIVE_RELEASE: releaseBefore, BLITZ_EXPECTED_DEMO_RELEASE: releaseBefore }, /shell baseline uses BLITZ_EXPECTED_LIVE_RELEASE/],
    [{ BLITZ_EXPECTED_LIVE_RELEASE: releaseBefore }, /demo baseline uses BLITZ_EXPECTED_DEMO_RELEASE/],
    [{ BLITZ_RELEASE_BASELINE: 'demo', BLITZ_EXPECTED_LIVE_RELEASE: releaseBefore }, /demo baseline uses BLITZ_EXPECTED_DEMO_RELEASE/],
    [{}, /exact expected live release name is required/],
  ];
  try {
    for (const [env, pattern] of cases) {
      const result = refuse(bin, env);
      assert.notEqual(result.status, 0, JSON.stringify(env));
      assert.match(result.stderr, pattern, JSON.stringify(env));
      assert.doesNotMatch(`${result.stdout}\n${result.stderr}`, /STEP_C: deploying|Authorized Firebase CLI missing/);
    }
  } finally {
    await rm(bin, { recursive: true, force: true });
  }
});

// Runs the real deploy script, in a repository copy, with stubbed cloud tools.
// mode:
//   ok             live shell baseline, deploy, live files equal the build
//   live-is-demo   the fictional demo is live (app.js page, ciphertext 200)
//   wrong-release  the operator-supplied release is not the live one
//   cipher-live    a shell page is live but /data.enc.json is still served
//   post-mismatch  after deploy the live shell.js is not the local build
//   demo-baseline  default demo baseline while a shell is live (today's production)
async function runUpdate(mode) {
  const work = await mkdtemp(path.join(os.tmpdir(), 'blitz-hosting-update-'));
  const repo = path.join(work, 'repo');
  const bin = path.join(work, 'bin');
  const state = path.join(work, 'state');
  const tmp = path.join(work, 'tmp');
  try {
    await mkdir(tmp);
    await mkdir(repo);
    await mkdir(bin);
    await mkdir(state);
    for (const entry of ['scripts', 'secure', 'docs']) {
      await cp(path.join(root, entry), path.join(repo, entry), { recursive: true });
    }
    for (const file of ['firebase.secure-blitz.json', '.firebaserc', 'package.json']) {
      await cp(path.join(root, file), path.join(repo, file));
    }
    await symlink(path.join(root, 'node_modules'), path.join(repo, 'node_modules'), 'dir');
    const operatorConfig = path.join(work, 'secure-config.local.json');
    await writeFile(operatorConfig, JSON.stringify(webConfig()), { mode: 0o600 });
    const previousShell = await builtShell(work, 'AIzaSyPREVIOUSLIVESHELLKEY0000000000000');
    const demoDir = path.join(work, 'demo');
    await mkdir(demoDir);
    await cp(path.join(root, 'docs', 'index.html'), path.join(demoDir, 'index.html'));
    await writeFile(path.join(demoDir, 'config.js'), '// demo has no secure config\n');
    await writeFile(path.join(demoDir, 'shell.js'), '// demo has no shell\n');
    const sites = path.join(work, 'sites.json');
    await writeFile(sites, JSON.stringify({
      status: 'success',
      result: { sites: [project, `${project}-app`, `${project}-prep`, site].map((id) => ({ name: `projects/${project}/sites/${id}` })) },
    }));
    const logs = { firebase: path.join(work, 'firebase.log'), npm: path.join(work, 'npm.log'), curl: path.join(work, 'curl.log') };
    for (const file of Object.values(logs)) await writeFile(file, '');

    await exe(path.join(bin, 'git'), `#!/bin/sh
case "$1" in
  rev-parse) printf '%s\\n' "$BLITZ_APPROVED_COMMIT" ;;
  status) ;;
  *) echo "unexpected git: $*" >&2; exit 1 ;;
esac
`);
    await exe(path.join(bin, 'gcloud'), `#!/bin/sh
case " $* " in
  *' print-access-token '*) printf '%s\\n' 'ya29.synthetic-hosting-update-token-for-tests' ;;
  *) printf '%s\\n' False ;;
esac
`);
    await exe(path.join(bin, 'firebase'), `#!/bin/sh
printf '%s\\n' "$*" >> "$STUB_FIREBASE_LOG"
case " $* " in
  *' deploy '*) printf '%s\\n' DEPLOY >> "$STUB_FIREBASE_LOG"; : > "$STUB_STATE/deployed"; exit 0 ;;
  *' hosting:sites:list '*) cat "$STUB_SITES" ;;
  *) echo "unexpected firebase: $*" >&2; exit 1 ;;
esac
`);
    await exe(path.join(bin, 'npm'), `#!/bin/sh
printf '%s\\n' "$*" >> "$STUB_NPM_LOG"
for name in BLITZ_APPROVE_SECURE_SHELL_DEPLOY BLITZ_APPROVED_COMMIT BLITZ_EXPECTED_DEMO_RELEASE BLITZ_EXPECTED_LIVE_RELEASE BLITZ_RELEASE_BASELINE; do
  if env | grep -q "^$name="; then printf '%s\\n' "APPROVAL_VAR_PRESENT $name" >> "$STUB_NPM_LOG"; fi
done
if [ "$1" = run ] && [ "$2" = test:secure ]; then
  printf '%s\\n' "nonce=$BLITZ_SECURE_ATTEST_NONCE" tests=7 pass=7 fail=0 cancelled=0 skipped=0 todo=0 iphone=pass > "$BLITZ_SECURE_ATTEST_PATH"
fi
exit 0
`);
    await exe(path.join(bin, 'curl'), `#!${process.execPath}
const fs = require('node:fs');
const path = require('node:path');
const args = process.argv.slice(2);
const env = process.env;
let out = null; let writeOut = null; let fail = false; const headers = [];
let url = null;
for (let i = 0; i < args.length; i++) {
  const a = args[i];
  if (a === '-o' || a === '--output') out = args[++i];
  else if (a === '--write-out') writeOut = args[++i];
  else if (a === '-H') headers.push(args[++i]);
  else if (a === '--max-time' || a === '--retry') i++;
  else if (a === '--fail') fail = true;
  else if (a === '-L' || a === '--location') { process.stderr.write('redirects not allowed'); process.exit(2); }
  else if (/^https:\\/\\//.test(a)) url = a;
}
fs.appendFileSync(env.STUB_CURL_LOG, url + '\\n');
const deployed = fs.existsSync(path.join(env.STUB_STATE, 'deployed'));
const mode = env.STUB_MODE;
const site = 'https://${site}.web.app';
let status = 404; let body = '';
if (url === 'https://firebasehosting.googleapis.com/v1beta1/sites/${site}/channels/live') {
  const auth = headers.find((h) => h.startsWith('@'));
  if (!auth || !/^Authorization: Bearer ya29\\./.test(fs.readFileSync(auth.slice(1), 'utf8'))) { status = 401; }
  else {
    status = 200;
    const release = deployed ? '${releaseAfter}' : '${releaseBefore}';
    const version = deployed ? '${versionAfter}' : '${versionBefore}';
    body = JSON.stringify({ name: 'sites/${site}/channels/live', url: site, release: { name: release, type: 'DEPLOY', version: { name: 'sites/${site}/versions/' + version, status: 'FINALIZED' } } });
  }
} else {
  const demoLive = !deployed && (mode === 'live-is-demo');
  const dir = deployed ? env.STUB_POST_DIR : (demoLive ? env.STUB_DEMO_DIR : env.STUB_PRE_DIR);
  const name = url === site + '/' ? 'index.html' : url.slice(site.length + 1);
  if (name === 'data.enc.json') {
    if (demoLive || (mode === 'cipher-live' && !deployed)) { status = 200; body = fs.readFileSync(env.STUB_CIPHER, 'utf8'); }
  } else if (['index.html', 'config.js', 'shell.js'].includes(name)) {
    status = 200; body = fs.readFileSync(path.join(dir, name), 'utf8');
    if (deployed && mode === 'post-mismatch' && name === 'shell.js') body += '\\n// tampered after deploy\\n';
  }
}
if (fail && status >= 400) { process.stderr.write('curl: (22) The requested URL returned error: ' + status + '\\n'); process.exit(22); }
if (out && out !== '/dev/null') fs.writeFileSync(out, body);
else if (!out) process.stdout.write(body);
if (writeOut === '%{http_code}') process.stdout.write(String(status));
`);
    const env = cleanEnv({
      PATH: `${bin}:${process.env.PATH}`,
      BLITZ_APPROVE_SECURE_SHELL_DEPLOY: 'YES',
      BLITZ_APPROVED_COMMIT: approved,
      BLITZ_SECURE_CONFIG: operatorConfig,
      TMPDIR: tmp,
      STUB_MODE: mode,
      STUB_STATE: state,
      STUB_SITES: sites,
      STUB_FIREBASE_LOG: logs.firebase,
      STUB_NPM_LOG: logs.npm,
      STUB_CURL_LOG: logs.curl,
      STUB_PRE_DIR: previousShell,
      STUB_DEMO_DIR: demoDir,
      STUB_POST_DIR: path.join(repo, '.firebase-blitz-private-shell'),
      STUB_CIPHER: path.join(root, 'docs', 'data.enc.json'),
    });
    if (mode === 'demo-baseline') {
      env.BLITZ_EXPECTED_DEMO_RELEASE = releaseBefore;
    } else {
      env.BLITZ_RELEASE_BASELINE = 'shell';
      env.BLITZ_EXPECTED_LIVE_RELEASE = mode === 'wrong-release' ? `sites/${site}/channels/live/releases/1` : releaseBefore;
    }
    const result = spawnSync('bash', [path.join(repo, 'scripts', 'deploy-secure-blitz.sh')], {
      cwd: repo, encoding: 'utf8', timeout: 240000, env,
    });
    const read = async (file) => readFile(file, 'utf8');
    // Scratch directories (fetched live files, token) must be gone on every exit path.
    const leftovers = (await readdir(tmp, { withFileTypes: true })).filter((e) => e.isDirectory()).map((e) => e.name);
    return {
      result,
      firebase: await read(logs.firebase),
      npm: await read(logs.npm),
      curl: await read(logs.curl),
      leftovers,
    };
  } finally {
    await rm(work, { recursive: true, force: true });
  }
}

function assertClean(run) {
  assert.deepEqual(run.leftovers, [], 'scratch directories were left behind');
}

function deployCount(text) {
  return text.split('\n').filter((line) => line === 'DEPLOY').length;
}

test('shell baseline: one hosting:blitz deploy, exact rollback, live files equal the approved build', { timeout: 300000 }, async () => {
  const run = await runUpdate('ok');
  assertClean(run);
  const { result, firebase, npm, curl } = run;
  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  assert.equal(deployCount(firebase), 1);
  assert.match(firebase, /^deploy --config firebase\.secure-blitz\.json --only hosting:blitz --project master-intelligence-5496f --non-interactive$/m);
  assert.doesNotMatch(firebase, /hosting:clone|hosting:disable|firestore|functions|storage/);
  assert.match(result.stdout, /^STEP_C_BASELINE=shell$/m);
  assert.match(result.stdout, new RegExp(`^STEP_C_LIVE_RELEASE=${releaseBefore}$`, 'm'));
  assert.match(result.stdout, new RegExp(`^STEP_C_NEW_RELEASE=${releaseAfter}$`, 'm'));
  assert.match(result.stdout, new RegExp(`^STEP_C_ROLLBACK_COMMAND=firebase hosting:clone --project ${project} --non-interactive ${site}@${versionBefore} ${site}:live$`, 'm'));
  assert.match(result.stdout, /STEP_C_DEPLOY_VERIFIED/);
  assert.doesNotMatch(npm, /APPROVAL_VAR_PRESENT/);
  assert.doesNotMatch(`${result.stdout}\n${result.stderr}`, /ya29\./);
  // Baseline read: shell files and ciphertext 404 before deploy; same three files after.
  assert.equal(curl.split('\n').filter((u) => u === `https://${site}.web.app/shell.js`).length, 2);
  assert.equal(curl.split('\n').filter((u) => u === `https://${site}.web.app/data.enc.json`).length, 2);
});

test('shell baseline refuses a live fictional demo before deploy', { timeout: 300000 }, async () => {
  const run = await runUpdate('live-is-demo');
  assertClean(run);
  const { result, firebase } = run;
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /not a production secure shell/);
  assert.equal(deployCount(firebase), 0);
  assert.doesNotMatch(result.stderr, /STEP_C_ROLLBACK_COMMAND/);
});

test('shell baseline refuses a live shell that still serves public ciphertext', { timeout: 300000 }, async () => {
  const run = await runUpdate('cipher-live');
  assertClean(run);
  const { result, firebase } = run;
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /not a production secure shell with no public ciphertext/);
  assert.equal(deployCount(firebase), 0);
});

test('shell baseline refuses when the live release is not the operator-verified one', { timeout: 300000 }, async () => {
  const run = await runUpdate('wrong-release');
  assertClean(run);
  const { result, firebase } = run;
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /does not equal the explicitly verified shell release/);
  assert.equal(deployCount(firebase), 0);
});

test('a live shell that differs from the approved build after deploy fails and prints the exact rollback', { timeout: 300000 }, async () => {
  const run = await runUpdate('post-mismatch');
  assertClean(run);
  const { result, firebase } = run;
  assert.notEqual(result.status, 0);
  assert.equal(deployCount(firebase), 1);
  assert.match(result.stderr, /not byte-identical to the approved local build/);
  assert.match(result.stderr, new RegExp(`STEP_C_ROLLBACK_COMMAND=firebase hosting:clone --project ${project} --non-interactive ${site}@${versionBefore} ${site}:live`));
  assert.doesNotMatch(result.stdout, /STEP_C_DEPLOY_VERIFIED/);
  assert.doesNotMatch(firebase, /hosting:clone/);
});

test('the default demo baseline cannot overwrite an already-live shell', { timeout: 300000 }, async () => {
  const run = await runUpdate('demo-baseline');
  assertClean(run);
  const { result, firebase } = run;
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Cannot verify existing fictional demo/);
  assert.equal(deployCount(firebase), 0);
});
