// F2/F3 end to end: the real deploy wrapper against stubbed cloud tools.
// Fictional data only. See tests/helpers/hosting-stubs.mjs for each mode.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { deployCount, project, runDeploy, site, versionAfter, versionBefore } from './helpers/hosting-stubs.mjs';
import { SECURE_SHELL_FILES } from '../scripts/verify-secure-shell.mjs';

const ROLLBACK = new RegExp(`STEP_C_ROLLBACK_COMMAND=firebase hosting:clone --project ${project} --non-interactive ${site}@${versionBefore} ${site}:live`);

function combined(run) {
  return `${run.result.stdout}\n${run.result.stderr}`;
}

function assertNoLeftovers(run) {
  assert.deepEqual(run.tmpLeftovers, [], 'release root or fetch directories were left behind');
  assert.doesNotMatch(combined(run), /ya29\./);
}

function assertStoppedBeforeDeploy(run, pattern) {
  assert.notEqual(run.result.status, 0, combined(run));
  assert.match(run.result.stderr, pattern);
  assert.equal(deployCount(run.firebase), 0);
  assert.doesNotMatch(combined(run), /STEP_C_DEPLOY_VERIFIED/);
  assertNoLeftovers(run);
}

function assertStoppedAfterDeploy(run, pattern) {
  assert.notEqual(run.result.status, 0, combined(run));
  assert.match(run.result.stderr, pattern);
  assert.equal(deployCount(run.firebase), 1);
  assert.match(run.result.stderr, ROLLBACK);
  assert.doesNotMatch(run.result.stdout, /STEP_C_DEPLOY_VERIFIED/);
  assert.doesNotMatch(run.firebase, /hosting:clone/);
  assertNoLeftovers(run);
}

test('F2: the deploy reads only a frozen private release and serves exactly its manifest', { timeout: 300000 }, async () => {
  const run = await runDeploy({ mode: 'ok' });
  assert.equal(run.result.status, 0, combined(run));
  assert.equal(deployCount(run.firebase), 1);
  assert.match(run.firebase, /^deploy --config \S+\/blitz-release-[^/\s]+\/firebase\.json --only hosting:blitz --project master-intelligence-5496f --non-interactive --json$/m);
  assert.ok(run.deployedConfig.includes('/blitz-release-') && !run.deployedConfig.startsWith(run.repo));
  assert.deepEqual(run.deployedFiles, SECURE_SHELL_FILES);
  assert.match(run.result.stdout, /^STEP_C_RELEASE_MANIFEST_SHA256=[0-9a-f]{64}$/m);
  assert.match(run.result.stdout, /STEP_C_DEPLOY_VERIFIED: .*manifest [0-9a-f]{64}; exact files, headers and CSP/);
  assertNoLeftovers(run);
});

test('F2: a fictional plaintext export dropped into the build directory after review is never deployed', { timeout: 300000 }, async () => {
  const run = await runDeploy({ mode: 'export-in-build-dir' });
  assert.equal(run.result.status, 0, combined(run));
  assert.deepEqual(run.deployedFiles, SECURE_SHELL_FILES);
  assert.equal(run.deployedFiles.some((file) => /export|cache/.test(file)), false);
  assertNoLeftovers(run);
});

test('F2: a change to the reviewed build after freezing stops before deploy', { timeout: 300000 }, async () => {
  const run = await runDeploy({ mode: 'tamper-before-deploy' });
  assertStoppedBeforeDeploy(run, /Frozen release changed before deploy|Release file changed after freeze/);
});

test('F2: a file added while the CLI uploads fails verification and prints the exact rollback', { timeout: 300000 }, async () => {
  const run = await runDeploy({ mode: 'tamper-during-deploy' });
  assertStoppedAfterDeploy(run, /Frozen release changed during deploy|not exactly the frozen manifest/);
});

test('F2: a live version listing any file outside the manifest fails', { timeout: 300000 }, async () => {
  const run = await runDeploy({ mode: 'version-extra' });
  assertStoppedAfterDeploy(run, /Live version files or content hashes are not exactly the frozen manifest/);
});

test('F3: a rollback target with anything beyond the fictional demo files is refused before deploy', { timeout: 300000 }, async () => {
  const run = await runDeploy({ mode: 'rollback-extra' });
  assertStoppedBeforeDeploy(run, /not a trustworthy baseline/);
});

for (const [mode, label] of [
  ['weak-csp', 'a CSP header weakened with unsafe-inline'],
  ['no-xfo', 'a missing X-Frame-Options header'],
  ['report-only', 'an added report-only CSP'],
  ['dup-csp', 'a second CSP header'],
  ['redirect', 'a redirect on shell.js'],
  ['cdn-mismatch', 'live bytes that differ from the manifest'],
  ['missing-404', 'a manifest file that answers 404'],
  ['extra-script', 'an unrelated script in the live page'],
]) {
  test(`F3: ${label} after deploy fails and prints the exact rollback`, { timeout: 300000 }, async () => {
    const run = await runDeploy({ mode });
    assertStoppedAfterDeploy(run, /do not match the frozen release/);
  });
}

// R1: the uploaded version, its content hashes and the channel after
// verification are all bound to the frozen release.
test('R1: the deploy binds the version the CLI reported and prints it', { timeout: 300000 }, async () => {
  const run = await runDeploy({ mode: 'ok' });
  assert.equal(run.result.status, 0, combined(run));
  assert.match(run.result.stdout, new RegExp(`^STEP_C_DEPLOYED_VERSION=sites/${site}/versions/${versionAfter}$`, 'm'));
  assertNoLeftovers(run);
});

for (const [mode, label, pattern] of [
  ['live-not-deployed', 'another version with the same files is live after the deploy', /does not serve the version this deploy uploaded/],
  ['version-hash-stale', 'the uploaded version holds different content under the right names', /content hashes are not exactly the frozen manifest/],
  ['drift-after-verify', 'the live channel changes after the release was verified', /channel changed after verification/],
]) {
  test(`R1: refuses when ${label}`, { timeout: 300000 }, async () => {
    const run = await runDeploy({ mode });
    assertStoppedAfterDeploy(run, pattern);
  });
}
