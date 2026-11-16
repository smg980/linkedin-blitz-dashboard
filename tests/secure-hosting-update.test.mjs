// Shell -> shell Hosting update path for deploy-secure-blitz.sh.
// Every cloud command (firebase, gcloud, curl) and git are stubs on PATH. The
// script runs from a temporary copy of the repository, so it never shares the
// real .firebase-blitz-private-shell output with other test files.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmod, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { assertLiveShell } from '../scripts/secure-hosting-guard.mjs';
import { buildSecureShell } from '../scripts/build-secure-shell.mjs';
import { SECURE_SHELL_FILES } from '../scripts/verify-secure-shell.mjs';
import { deployCount, runDeploy } from './helpers/hosting-stubs.mjs';

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
    // F3: weakened policies and extra scripts are refused, not just a missing CSP.
    assert.throws(() => assertLiveShell({ ...live, html: live.html.replace("script-src 'self'", "script-src 'self' 'unsafe-inline'") }), /exact production policy/);
    assert.throws(() => assertLiveShell({ ...live, html: live.html.replace("script-src 'self'", "script-src 'self' 'unsafe-eval'") }), /exact production policy/);
    assert.throws(() => assertLiveShell({ ...live, html: live.html.replace("script-src 'self'", "script-src 'self' https://cdn.example") }), /exact production policy/);
    assert.throws(() => assertLiveShell({ ...live, html: live.html.replace('</body>', '<script src="analytics.js" defer></script></body>') }), /scripts other than/);
    assert.throws(() => assertLiveShell({ ...live, html: live.html.replace('</body>', '<script>alert(1)</script></body>') }), /scripts other than/);
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
    // R2
    [{ BLITZ_RELEASE_BASELINE: 'shell', BLITZ_EXPECTED_LIVE_RELEASE: releaseBefore }, /needs BLITZ_APPROVED_BASELINE_RECORD/],
    [{ BLITZ_RELEASE_BASELINE: 'shell', BLITZ_EXPECTED_LIVE_RELEASE: releaseBefore, BLITZ_APPROVED_BASELINE_RECORD: '/x', BLITZ_APPROVED_BASELINE_RECORD_SHA256: 'abc' }, /needs BLITZ_APPROVED_BASELINE_RECORD/],
    [{ BLITZ_EXPECTED_DEMO_RELEASE: releaseBefore, BLITZ_APPROVED_BASELINE_RECORD: '/x' }, /demo baseline takes no baseline record/],
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

// The shell -> shell update path runs the real deploy script against the shared
// stub harness (tests/helpers/hosting-stubs.mjs); see that file for each mode.
const ROLLBACK = new RegExp(`STEP_C_ROLLBACK_COMMAND=firebase hosting:clone --project ${project} --non-interactive ${site}@${versionBefore} ${site}:live`);

function runUpdate(mode, baseline = 'shell', options = {}) {
  return runDeploy({ mode, baseline, buildShell: builtShell, ...options });
}

function assertClean(run) {
  assert.deepEqual(run.tmpLeftovers, [], 'scratch directories were left behind');
  assert.doesNotMatch(`${run.result.stdout}\n${run.result.stderr}`, /ya29\./);
}

function count(text, url) {
  return text.split('\n').filter((u) => u === url).length;
}

test('shell baseline: one hosting:blitz deploy from the frozen release, exact rollback, every live byte equals the manifest', { timeout: 300000 }, async () => {
  const run = await runUpdate('ok');
  assertClean(run);
  const { result, firebase, npm, curl } = run;
  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  assert.equal(deployCount(firebase), 1);
  assert.match(firebase, /^deploy --config \S+\/blitz-release-[^/\s]+\/firebase\.json --only hosting:blitz --project master-intelligence-5496f --non-interactive --json$/m);
  assert.doesNotMatch(firebase, /hosting:clone|hosting:disable|firestore|functions|storage/);
  assert.deepEqual(run.deployedFiles, SECURE_SHELL_FILES);
  assert.match(result.stdout, /^STEP_C_BASELINE=shell$/m);
  assert.match(result.stdout, new RegExp(`^STEP_C_LIVE_RELEASE=${releaseBefore}$`, 'm'));
  assert.match(result.stdout, new RegExp(`^STEP_C_NEW_RELEASE=${releaseAfter}$`, 'm'));
  assert.match(result.stdout, ROLLBACK);
  assert.match(result.stdout, /^STEP_C_RELEASE_MANIFEST_SHA256=[0-9a-f]{64}$/m);
  assert.match(result.stdout, /STEP_C_DEPLOY_VERIFIED/);
  assert.doesNotMatch(npm, /APPROVAL_VAR_PRESENT/);
  // Every shell path and "/" before (baseline) and after (manifest); the rollback version's and new version's file lists.
  assert.equal(count(curl, `https://${site}.web.app/shell.js`), 2);
  assert.equal(count(curl, `https://${site}.web.app/fonts/Manrope-latin.woff2`), 2);
  assert.equal(count(curl, `https://${site}.web.app/data.enc.json`), 2);
  assert.equal(count(curl, `https://firebasehosting.googleapis.com/v1beta1/sites/${site}/versions/${versionBefore}/files`), 1);
  assert.equal(count(curl, `https://firebasehosting.googleapis.com/v1beta1/sites/${site}/versions/${versionAfter}/files`), 1);
});

test('shell baseline refuses a live fictional demo before deploy', { timeout: 300000 }, async () => {
  const run = await runUpdate('live-is-demo');
  assertClean(run);
  assert.notEqual(run.result.status, 0);
  assert.match(run.result.stderr, /production secure shell with no public ciphertext/);
  assert.equal(deployCount(run.firebase), 0);
  assert.doesNotMatch(run.result.stderr, /STEP_C_ROLLBACK_COMMAND/);
});

test('shell baseline refuses a live shell that still serves public ciphertext', { timeout: 300000 }, async () => {
  const run = await runUpdate('cipher-live');
  assertClean(run);
  assert.notEqual(run.result.status, 0);
  assert.match(run.result.stderr, /production secure shell with no public ciphertext/);
  assert.equal(deployCount(run.firebase), 0);
});

test('shell baseline refuses when the live release is not the operator-verified one', { timeout: 300000 }, async () => {
  const run = await runUpdate('wrong-release');
  assertClean(run);
  assert.notEqual(run.result.status, 0);
  assert.match(run.result.stderr, /does not equal the explicitly verified shell release/);
  assert.equal(deployCount(run.firebase), 0);
});

test('a live shell that differs from the frozen release after deploy fails and prints the exact rollback', { timeout: 300000 }, async () => {
  const run = await runUpdate('cdn-mismatch');
  assertClean(run);
  assert.notEqual(run.result.status, 0);
  assert.equal(deployCount(run.firebase), 1);
  assert.match(run.result.stderr, /do not match the frozen release/);
  assert.match(run.result.stderr, ROLLBACK);
  assert.doesNotMatch(run.result.stdout, /STEP_C_DEPLOY_VERIFIED/);
  assert.doesNotMatch(run.firebase, /hosting:clone/);
});

test('the default demo baseline cannot overwrite an already-live shell', { timeout: 300000 }, async () => {
  const run = await runUpdate('demo-baseline-shell-live', 'demo');
  assertClean(run);
  assert.notEqual(run.result.status, 0);
  assert.match(run.result.stderr, /Cannot verify existing fictional demo/);
  assert.equal(deployCount(run.firebase), 0);
});

// F3: the rollback baseline itself must pass the exact live checks before
// anything is deployed over it.
for (const [mode, label] of [
  ['baseline-weak-csp', 'a CSP header weakened with unsafe-inline'],
  ['baseline-no-xfo', 'a missing X-Frame-Options header'],
  ['baseline-report-only', 'an added report-only CSP'],
  ['baseline-dup-csp', 'a second CSP header'],
  ['baseline-redirect', 'a redirect on shell.js'],
  ['baseline-missing-404', 'a shell file that answers 404'],
  ['baseline-extra-script', 'an unrelated script in the page'],
]) {
  test(`F3: a live shell baseline with ${label} is refused before deploy`, { timeout: 300000 }, async () => {
    const run = await runUpdate(mode);
    assertClean(run);
    assert.notEqual(run.result.status, 0, `${run.result.stdout}\n${run.result.stderr}`);
    assert.match(run.result.stderr, /production secure shell with no public ciphertext/);
    assert.equal(deployCount(run.firebase), 0);
    assert.doesNotMatch(run.result.stderr, /STEP_C_ROLLBACK_COMMAND/);
  });
}

test('F3: a shell rollback version that lists any extra file is refused before deploy', { timeout: 300000 }, async () => {
  const run = await runUpdate('rollback-extra');
  assertClean(run);
  assert.notEqual(run.result.status, 0);
  assert.match(run.result.stderr, /not exactly the approved secure shell baseline; it is not a trustworthy baseline/);
  assert.equal(deployCount(run.firebase), 0);
});

// F2 on the update path: same frozen-release guarantees as the first release.
test('F2: on the update path a fictional export in the build directory is never deployed', { timeout: 300000 }, async () => {
  const run = await runUpdate('export-in-build-dir');
  assertClean(run);
  assert.equal(run.result.status, 0, `${run.result.stdout}\n${run.result.stderr}`);
  assert.deepEqual(run.deployedFiles, SECURE_SHELL_FILES);
});

for (const [mode, pattern] of [
  ['tamper-during-deploy', /Frozen release changed during deploy|not exactly the frozen manifest/],
  ['weak-csp', /do not match the frozen release/],
  ['redirect', /do not match the frozen release/],
]) {
  test(`F2/F3: on the update path ${mode} after deploy fails and prints the exact rollback`, { timeout: 300000 }, async () => {
    const run = await runUpdate(mode);
    assertClean(run);
    assert.notEqual(run.result.status, 0);
    assert.equal(deployCount(run.firebase), 1);
    assert.match(run.result.stderr, pattern);
    assert.match(run.result.stderr, ROLLBACK);
    assert.doesNotMatch(run.result.stdout, /STEP_C_DEPLOY_VERIFIED/);
  });
}

// R2: the shell rollback baseline must be an independently approved release
// record: the live version, its Hosting content hashes and every served byte.
for (const [mode, label, pattern] of [
  ['baseline-arbitrary-js', 'a live shell.js that passes every structural check but is not the approved one', /not the approved production secure shell/],
  ['baseline-version-hash', 'a rollback version whose content hash is not the approved record', /not exactly the approved secure shell baseline/],
  ['baseline-record-other-version', 'an approved record for a different version', /not the approved baseline version/],
]) {
  test(`R2: refuses before deploy when the baseline has ${label}`, { timeout: 300000 }, async () => {
    const run = await runUpdate(mode);
    assertClean(run);
    assert.notEqual(run.result.status, 0, `${run.result.stdout}\n${run.result.stderr}`);
    assert.match(run.result.stderr, pattern);
    assert.equal(deployCount(run.firebase), 0);
    assert.doesNotMatch(run.result.stderr, /STEP_C_ROLLBACK_COMMAND/);
  });
}

test('R2: a shell baseline without an approved record is refused before any test or cloud call', { timeout: 300000 }, async () => {
  const run = await runUpdate('ok', 'shell', { record: false });
  assert.notEqual(run.result.status, 0);
  assert.match(run.result.stderr, /needs BLITZ_APPROVED_BASELINE_RECORD/);
  assert.equal(run.npm, '');
  assert.equal(run.curl, '');
  assert.equal(deployCount(run.firebase), 0);
});

test('R2: a verified deploy prints a release record that is itself a valid approved baseline', { timeout: 300000 }, async () => {
  const { parseReleaseRecord } = await import('../scripts/secure-release.mjs');
  const run = await runUpdate('ok');
  assert.equal(run.result.status, 0, `${run.result.stdout}\n${run.result.stderr}`);
  const text = `${run.result.stdout.match(/^STEP_C_RELEASE_RECORD=(.*)$/m)[1]}\n`;
  const digest = run.result.stdout.match(/^STEP_C_RELEASE_RECORD_SHA256=([0-9a-f]{64})$/m)[1];
  const record = parseReleaseRecord(text, digest, site);
  assert.equal(record.versionName, `sites/${site}/versions/${versionAfter}`);
  assert.deepEqual(record.files.map((f) => f.path), SECURE_SHELL_FILES);
  assert.throws(() => parseReleaseRecord(text.replace('"size":', '"size": '), digest, site), /approved digest/);
});
