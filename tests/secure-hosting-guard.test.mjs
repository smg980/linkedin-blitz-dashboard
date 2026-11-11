import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { assertSecureTarget, assertPrivateWebConfig, currentLiveRelease } from '../scripts/secure-hosting-guard.mjs';

const site = 'master-intelligence-5496f-lb';
const project = 'master-intelligence-5496f';
const rc = { projects: { default: project }, targets: { [project]: { hosting: { blitz: [site] } } } };
const config = { hosting: { target: 'blitz', public: '.firebase-blitz-private-shell' } };
const web = {
  firebase: {
    apiKey: 'AIzaSyDUMMYPUBLICWEBCONFIGKEY000000000',
    authDomain: 'master-intelligence-5496f.firebaseapp.com',
    projectId: project,
    appId: '1:000000000000:web:abcdef0123456789',
  },
  useEmulators: false,
};
const parse = (v) => assertPrivateWebConfig(`globalThis.BLITZ_SECURE_CONFIG = ${JSON.stringify(v)};\n`);
const script = readFileSync('scripts/deploy-secure-blitz.sh', 'utf8');
const scriptCode = script.split('\n').filter((line) => !line.trim().startsWith('#')).join('\n');

function channel(patch = {}) {
  const release = {
    name: `sites/${site}/channels/live/releases/123`,
    type: 'DEPLOY',
    version: { name: `sites/${site}/versions/456`, status: 'FINALIZED' },
    releaseUser: { email: 'release-user@example.com' },
    ...patch.release,
  };
  return {
    name: `sites/${site}/channels/live`,
    url: `https://${site}.web.app`,
    release,
    ...patch.channel,
  };
}

function cleanChildEnv(overrides = {}, base = process.env) {
  const env = {};
  for (const [key, value] of Object.entries(base)) {
    if (typeof value !== 'string') continue;
    if (key.startsWith('BLITZ_') || /PASSPHRASE/i.test(key)) continue;
    if (key === 'CI' || key === 'GITHUB_ACTIONS' || key === 'FIREBASE_TOKEN' || key === 'GOOGLE_APPLICATION_CREDENTIALS') continue;
    env[key] = value;
  }
  return { ...env, ...overrides };
}

function runDeploy(overrides = {}, base = process.env) {
  return spawnSync('bash', ['scripts/deploy-secure-blitz.sh'], {
    env: cleanChildEnv(overrides, base), encoding: 'utf8', timeout: 10000,
  });
}

test('private target is exact and rejects cross-site targets', () => {
  assert.doesNotThrow(() => assertSecureTarget(rc, config));
  assert.doesNotThrow(() => assertSecureTarget(
    JSON.parse(readFileSync('.firebaserc', 'utf8')),
    JSON.parse(readFileSync('firebase.secure-blitz.json', 'utf8')),
  ));
  assert.throws(() => assertSecureTarget(rc, { hosting: { target: 'prep', public: '.firebase-blitz-private-shell' } }));
  assert.throws(() => assertSecureTarget(rc, { hosting: { target: 'blitz', public: '.firebase-blitz-demo' } }));
  assert.throws(() => assertSecureTarget(rc, { hosting: { ...config.hosting, rewrites: [{ source: '**', function: 'api' }] } }));
  assert.throws(() => assertSecureTarget({ ...rc, targets: { ...rc.targets, other: {} } }, config));
  assert.throws(() => assertSecureTarget(rc, { ...config, firestore: { rules: 'rules' } }));
  for (const other of [project, `${project}-app`, `${project}-prep`, site]) {
    assert.throws(
      () => assertSecureTarget(rc, { hosting: { ...config.hosting, site: other } }),
      /Unexpected private Hosting setting: site/,
    );
    assert.throws(() => assertSecureTarget({
      ...rc,
      targets: { [project]: { hosting: { blitz: [other === site ? project : other] } } },
    }, config));
  }
  assert.throws(() => assertSecureTarget({
    ...rc,
    targets: { [project]: { hosting: { blitz: [site, project] } } },
  }, config));
  assert.throws(() => assertSecureTarget({
    ...rc,
    targets: { [project]: { hosting: { blitz: [site], app: [`${project}-app`] } } },
  }, config));
  assert.throws(() => assertSecureTarget(rc, { hosting: { ...config.hosting, source: 'secure' } }), /Unexpected private Hosting setting: source/);
  assert.throws(() => assertSecureTarget(rc, { hosting: [config.hosting] }));
});

test('built production shell rejects wrong project, emulator settings, and non-public config', () => {
  assert.equal(parse(web).firebase.projectId, project);
  assert.equal(parse({ ...web, firebase: { ...web.firebase, authDomain: `${site}.web.app` } }).firebase.authDomain, `${site}.web.app`);
  assert.throws(() => parse({ ...web, useEmulators: true }));
  assert.throws(() => parse({ ...web, emulators: { authHost: '127.0.0.1' } }));
  assert.throws(() => parse({ ...web, firebase: { ...web.firebase, projectId: 'demo-blitz-secure' } }));
  assert.throws(() => parse({ ...web, firebase: { ...web.firebase, authDomain: 'attacker.example' } }));
  assert.throws(() => parse({ ...web, firebase: { ...web.firebase, authDomain: `${project}.web.app` } }));
  assert.throws(() => parse({ ...web, firebase: { ...web.firebase, authDomain: `${project}-app.web.app` } }));
  assert.throws(() => parse({ ...web, firebase: { ...web.firebase, authDomain: `${project}-prep.web.app` } }));
  assert.throws(() => parse({ ...web, firebase: { ...web.firebase, ownerUID: 'secret' } }));
  assert.throws(() => parse({ ...web, firebase: { ...web.firebase, storageBucket: `${project}.appspot.com` } }));
  assert.throws(() => parse({ ...web, firebase: { ...web.firebase, apiKey: 'REPLACE_ME' } }));
  assert.throws(() => parse({ ...web, firebase: { ...web.firebase, apiKey: 'public-web-key' } }));
  assert.throws(() => parse({ ...web, firebase: { ...web.firebase, apiKey: '-----BEGIN PRIVATE KEY-----' } }));
  assert.throws(() => parse({ ...web, firebase: { ...web.firebase, appId: '1:abc:web:xyz' } }));
});

test('live channel release is exact and rejects lists, wrong sites, and unrestorable versions', () => {
  const live = currentLiveRelease(JSON.stringify(channel()));
  assert.deepEqual(live, {
    release: `sites/${site}/channels/live/releases/123`,
    version: `sites/${site}/versions/456`,
    versionId: '456',
  });
  assert.equal(currentLiveRelease(JSON.stringify(channel({
    release: { name: `sites/${site}/releases/123`, type: 'TYPE_UNSPECIFIED' },
  }))).versionId, '456');
  const omitted = channel();
  delete omitted.release.type;
  assert.equal(currentLiveRelease(JSON.stringify(omitted)).release, `sites/${site}/channels/live/releases/123`);

  const rejects = [
    '{',
    'null',
    '[]',
    JSON.stringify({ releases: [], nextPageToken: 'next' }),
    JSON.stringify({ releases: [channel().release] }),
    JSON.stringify({ releases: [channel().release, channel().release] }),
    JSON.stringify(channel({ channel: { name: `sites/${site}/channels/preview` } })),
    JSON.stringify(channel({ channel: { name: `sites/${site}/channels/live-extra` } })),
    JSON.stringify(channel({ channel: { name: `projects/${project}/sites/${site}/channels/live` } })),
    JSON.stringify(channel({ channel: { url: `https://${project}-app.web.app` } })),
    JSON.stringify(channel({ channel: { url: `https://${site}.web.app/` } })),
    JSON.stringify(channel({ channel: { url: `https://${site}.firebaseapp.com` } })),
    JSON.stringify(channel({ release: { name: `sites/${project}-app/channels/live/releases/123` } })),
    JSON.stringify(channel({ release: { name: `sites/${project}-prep/channels/live/releases/123` } })),
    JSON.stringify(channel({ release: { name: `sites/${project}/channels/live/releases/123` } })),
    JSON.stringify(channel({ release: { name: `sites/${site}/channels/live/releases/123/extra` } })),
    JSON.stringify(channel({ release: { name: `sites/${site}/channels/preview/releases/123` } })),
    JSON.stringify(channel({ release: { name: `sites/${site}/releases/../../x` } })),
    JSON.stringify(channel({ release: { version: { name: `sites/${project}-app/versions/456`, status: 'FINALIZED' } } })),
    JSON.stringify(channel({ release: { version: { name: `sites/${site}/versions/456/extra`, status: 'FINALIZED' } } })),
    JSON.stringify(channel({ release: { version: { name: `sites/${site}/versions/456`, status: 'DELETED' } } })),
    JSON.stringify(channel({ release: { version: { name: `sites/${site}/versions/456`, status: 'EXPIRED' } } })),
    JSON.stringify(channel({ release: { version: { name: `sites/${site}/versions/456`, status: 'CREATED' } } })),
    JSON.stringify(channel({ release: { version: { name: `sites/${site}/versions/456` } } })),
    JSON.stringify(channel({ release: { type: 'SITE_DISABLE' } })),
    JSON.stringify(channel({ release: { type: 'ROLLBACK' } })),
    JSON.stringify(channel({ channel: { release: null } })),
  ];
  for (const body of rejects) {
    assert.throws(() => currentLiveRelease(body), (error) => {
      assert.doesNotMatch(error.message, /release-user@example.com/);
      return true;
    });
  }
});

test('release cli prints only the clone id and drops account identifiers', () => {
  const good = spawnSync(process.execPath, ['scripts/secure-hosting-guard.mjs', '--release'], {
    input: JSON.stringify(channel()), encoding: 'utf8', env: cleanChildEnv(),
  });
  assert.equal(good.status, 0);
  assert.equal(good.stdout, [
    `sites/${site}/channels/live/releases/123`,
    `sites/${site}/versions/456`,
    '456',
    '',
  ].join('\n'));
  assert.doesNotMatch(`${good.stdout}${good.stderr}`, /release-user@example.com|apiKey|ya29/);
  const paged = spawnSync(process.execPath, ['scripts/secure-hosting-guard.mjs', '--release'], {
    input: JSON.stringify({ releases: [channel().release], nextPageToken: 'next' }), encoding: 'utf8', env: cleanChildEnv(),
  });
  assert.notEqual(paged.status, 0);
  assert.match(paged.stderr, /not a paged list/);
  assert.equal(paged.stdout, '');
  const configured = spawnSync(process.execPath, ['scripts/secure-hosting-guard.mjs', '--assert-config'], {
    encoding: 'utf8', env: cleanChildEnv(),
  });
  assert.equal(configured.status, 0, configured.stderr);
  assert.match(configured.stdout, /hosting:blitz/);
});

test('secure deploy script can target only hosting:blitz and prints an exact clone rollback', () => {
  assert.equal(spawnSync('bash', ['-n', 'scripts/deploy-secure-blitz.sh'], { encoding: 'utf8', env: cleanChildEnv() }).status, 0);
  assert.deepEqual(scriptCode.match(/firebase deploy[^\n]*/g), [
    'firebase deploy --config firebase.secure-blitz.json --only "hosting:$TARGET" --project "$PROJECT" --non-interactive',
  ]);
  assert.deepEqual(scriptCode.match(/firebase hosting:clone[^\n]*/g), [
    'firebase hosting:clone --project ${PROJECT} --non-interactive ${SITE}@${previous_version_id} ${SITE}:live"',
  ]);
  assert.equal(scriptCode.split('firebase hosting:clone').length, 2);
  assert.match(scriptCode, /firebasehosting\.googleapis\.com\/v1beta1\/sites\/\$\{SITE\}\/channels\/live"/);
  assert.doesNotMatch(scriptCode, /pageSize|releases\?|pageToken|--location|(^|\s)-L(\s|$)|hosting:disable|sites:delete|firestore:|functions:|storage:|--only ['"]?hosting['"]?(?:\s|$)/);
  assert.doesNotMatch(scriptCode, /master-intelligence-5496f-app|master-intelligence-5496f-prep|hosting:app|hosting:prep/);
  assert.doesNotMatch(scriptCode, /\|\|\s*firebase|echo[^\n]*\$token|read -s|DASHBOARD_PASSPHRASE=/);
  assert.match(scriptCode, /BLITZ_APPROVE_SECURE_SHELL_DEPLOY/);
  assert.match(scriptCode, /cf657dfeadc74bc5091f1dce72f68ba83754677234760c3182920ff088fccccd/);
  assert.match(scriptCode, /-H @"\$token_file"/);
  assert.match(scriptCode, /Concurrent Hosting change detected/);
  assert.match(scriptCode, /deploy_verified=1/);
  const isolated = 'env -u BLITZ_APPROVE_SECURE_SHELL_DEPLOY \\\n    -u BLITZ_APPROVED_COMMIT \\\n    -u BLITZ_EXPECTED_DEMO_RELEASE \\\n    ';
  for (const [command, message] of [
    ['npm test', 'npm test failed.'],
    ['npm run verify:bundle', 'verify:bundle failed.'],
    ['npm run test:secure', 'test:secure failed.'],
  ]) {
    assert.ok(scriptCode.includes(`${isolated}${command} || stop '${message}'`), command);
  }
  assert.equal([...scriptCode.matchAll(/secure-hosting-guard\.mjs --assert-config \|\| stop 'Private Hosting config check failed\.'/g)].length, 2);
  assert.equal([...scriptCode.matchAll(/secure-hosting-guard\.mjs --assert-shell \|\| stop 'Secure shell output check failed\.'/g)].length, 2);
  assert.match(scriptCode, /build-secure-shell\.mjs --config "\$\{BLITZ_SECURE_CONFIG:-secure-config\.local\.json\}" \|\| stop 'Secure shell build failed\.'/);
});

function assertDeployRefusals(base) {
  const missing = runDeploy({}, base);
  assert.notEqual(missing.status, 0);
  assert.match(missing.stderr, /Explicit Step C opt-in is required/);
  assert.doesNotMatch(`${missing.stdout}\n${missing.stderr}`, /STEP_C: deploying|firebase deploy --config|recursive/);
  const ci = runDeploy({ CI: 'true', BLITZ_APPROVE_SECURE_SHELL_DEPLOY: 'YES' }, base);
  assert.notEqual(ci.status, 0);
  assert.match(ci.stderr, /Never deploy from CI/);
  assert.doesNotMatch(`${ci.stdout}\n${ci.stderr}`, /STEP_C: deploying|firebase deploy --config/);
  const secret = 'synthetic-review-passphrase';
  const passphrase = runDeploy({ BLITZ_APPROVE_SECURE_SHELL_DEPLOY: 'YES', DASHBOARD_PASSPHRASE: secret }, base);
  assert.notEqual(passphrase.status, 0);
  assert.match(passphrase.stderr, /No campaign passphrase/);
  assert.doesNotMatch(`${passphrase.stdout}\n${passphrase.stderr}`, new RegExp(secret));
  const wrong = runDeploy({ BLITZ_APPROVE_SECURE_SHELL_DEPLOY: 'YES', BLITZ_APPROVED_COMMIT: '0000000000000000000000000000000000000000' }, base);
  assert.notEqual(wrong.status, 0);
  assert.match(wrong.stderr, /not the approved commit/);
  assert.doesNotMatch(`${wrong.stdout}\n${wrong.stderr}`, /STEP_C: deploying|firebase deploy --config/);
}

test('secure deploy refuses CI, a missing opt-in, a passphrase, and the wrong commit', () => {
  assertDeployRefusals(process.env);
});

test('refusal cases ignore operator approval variables inherited from the parent', () => {
  const parent = {
    ...process.env,
    BLITZ_APPROVE_SECURE_SHELL_DEPLOY: 'YES',
    BLITZ_APPROVED_COMMIT: 'efea80ad8156a0756d0a329a3f7a7ebc5a8a8713',
    BLITZ_EXPECTED_DEMO_RELEASE: 'sites/x/channels/live/releases/1',
    BLITZ_SYNTHETIC_PASSPHRASE: 'parent-synthetic-passphrase',
    DASHBOARD_PASSPHRASE: 'parent-passphrase-must-not-leak',
    FIREBASE_TOKEN: 'parent-firebase-token',
    GOOGLE_APPLICATION_CREDENTIALS: '/tmp/parent-adc.json',
    CI: 'true',
    GITHUB_ACTIONS: 'true',
  };
  assertDeployRefusals(parent);
});

async function writeExecutable(file, body) {
  await writeFile(file, body, { mode: 0o755 });
  await chmod(file, 0o755);
}

async function deployStopsBeforeFirebase(mode) {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const dir = await mkdtemp(path.join(os.tmpdir(), 'blitz-deploy-gate-'));
  const bin = path.join(dir, 'bin');
  await mkdir(bin);
  const firebaseLog = path.join(dir, 'firebase.log');
  const npmLog = path.join(dir, 'npm.log');
  const sites = path.join(dir, 'sites.json');
  const config = path.join(dir, 'secure-config.json');
  const killed = path.join(dir, 'killed-gate.mjs');
  const approved = '1111111111111111111111111111111111111111';
  await writeFile(config, '{}\n');
  await writeFile(firebaseLog, '');
  await writeFile(npmLog, '');
  await writeFile(sites, JSON.stringify({
    status: 'success',
    result: {
      sites: [
        'master-intelligence-5496f',
        'master-intelligence-5496f-app',
        'master-intelligence-5496f-prep',
        'master-intelligence-5496f-lb',
      ].map((id) => ({ name: `projects/master-intelligence-5496f/sites/${id}` })),
    },
  }));
  const suite = path.join(root, 'scripts', 'run-secure-suite.mjs');
  await writeFile(killed, `import { integrationFailure, runRecordedIntegration, runSignalKilledIntegration } from ${JSON.stringify(pathToFileURL(suite).href)};
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

let watched;
const scratch = await fs.mkdtemp(path.join(os.tmpdir(), 'blitz-failed-child-'));
try {
  if (process.env.SECURE_GATE_MODE === 'failed') {
    const testFile = path.join(scratch, 'fail.test.mjs');
    await fs.writeFile(testFile, "import test from 'node:test';\\nimport assert from 'node:assert/strict';\\ntest('nope', () => { assert.equal(1, 2); });\\n");
    watched = await runRecordedIntegration(testFile);
  } else {
    watched = await runSignalKilledIntegration();
  }
} finally {
  await fs.rm(scratch, { recursive: true, force: true });
}
const failure = integrationFailure({ ...watched, execCode: 0, execSignal: null });
if (!failure) {
  console.error('integration child was treated as success');
  process.exit(0);
}
console.error(failure);
process.exit(1);
`);
  await writeExecutable(path.join(bin, 'git'), `#!/bin/sh
set -u
case "$1" in
  rev-parse) printf '%s\\n' "$BLITZ_APPROVED_COMMIT" ;;
  status) ;;
  *) echo "unexpected git: $*" >&2; exit 1 ;;
esac
`);
  await writeExecutable(path.join(bin, 'gcloud'), `#!/bin/sh
printf '%s\\n' False
`);
  await writeExecutable(path.join(bin, 'curl'), `#!/bin/sh
echo 'curl refused in deploy gate test' >&2
exit 1
`);
  await writeExecutable(path.join(bin, 'firebase'), `#!/bin/sh
set -u
printf '%s\\n' "$*" >> "$SECURE_GATE_FIREBASE_LOG"
case " $* " in
  *' deploy '*) printf '%s\\n' DEPLOY >> "$SECURE_GATE_FIREBASE_LOG"; exit 99 ;;
esac
cat "$SECURE_GATE_SITES"
`);
  await writeExecutable(path.join(bin, 'npm'), `#!/bin/sh
set -u
printf '%s\\n' "$*" >> "$SECURE_GATE_NPM_LOG"
if [ "$1" = "run" ] && [ "$2" = "test:secure" ]; then
  if [ "$SECURE_GATE_MODE" = "missing-chrome" ]; then
    exec "$SECURE_GATE_NODE" "$SECURE_GATE_SUITE"
  fi
  exec "$SECURE_GATE_NODE" "$SECURE_GATE_KILL"
fi
exit 0
`);
  const env = cleanChildEnv({
    BLITZ_APPROVE_SECURE_SHELL_DEPLOY: 'YES',
    BLITZ_APPROVED_COMMIT: approved,
    BLITZ_EXPECTED_DEMO_RELEASE: 'sites/x/channels/live/releases/1',
    BLITZ_SECURE_CONFIG: config,
    PATH: `${bin}:${process.env.PATH}`,
    SECURE_GATE_MODE: mode,
    SECURE_GATE_FIREBASE_LOG: firebaseLog,
    SECURE_GATE_NPM_LOG: npmLog,
    SECURE_GATE_SITES: sites,
    SECURE_GATE_NODE: process.execPath,
    SECURE_GATE_SUITE: suite,
    SECURE_GATE_KILL: killed,
  });
  if (mode === 'missing-chrome') env.CHROME_PATH = '/no/such/chrome-for-secure-gate';
  else delete env.CHROME_PATH;
  try {
    const result = spawnSync('bash', [path.join(root, 'scripts', 'deploy-secure-blitz.sh')], {
      cwd: root,
      encoding: 'utf8',
      timeout: 45000,
      env,
    });
    const firebaseText = await readFile(firebaseLog, 'utf8');
    const npmText = await readFile(npmLog, 'utf8');
    return { result, firebaseText, npmText };
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

test('missing Chrome stops the deploy script before firebase deploy', { timeout: 60000 }, async () => {
  const { result, firebaseText, npmText } = await deployStopsBeforeFirebase('missing-chrome');
  assert.notEqual(result.status, 0, result.stderr || result.stdout);
  assert.match(result.stderr, /STOP: test:secure failed/);
  assert.match(result.stderr, /CHROME_PATH/);
  assert.match(result.stderr, /Playwright chromium/);
  assert.match(npmText, /test:secure/);
  assert.doesNotMatch(`${result.stdout}\n${result.stderr}`, /STEP_C: deploying|firebase deploy --config/);
  assert.doesNotMatch(firebaseText, /deploy/);
});

test('a killed integration child stops the deploy script before firebase deploy', { timeout: 60000 }, async () => {
  const { result, firebaseText, npmText } = await deployStopsBeforeFirebase('killed');
  assert.notEqual(result.status, 0, result.stderr || result.stdout);
  assert.match(result.stderr, /STOP: test:secure failed/);
  assert.match(result.stderr, /integration child exited 137/);
  assert.match(npmText, /test:secure/);
  assert.doesNotMatch(`${result.stdout}\n${result.stderr}`, /STEP_C: deploying|firebase deploy --config/);
  assert.doesNotMatch(firebaseText, /deploy/);
});

test('a failed integration child stops the deploy script before firebase deploy', { timeout: 60000 }, async () => {
  const { result, firebaseText, npmText } = await deployStopsBeforeFirebase('failed');
  assert.notEqual(result.status, 0, result.stderr || result.stdout);
  assert.match(result.stderr, /STOP: test:secure failed/);
  assert.match(result.stderr, /fail 1/);
  assert.match(result.stderr, /integration child exited 1/);
  assert.match(npmText, /test:secure/);
  assert.doesNotMatch(`${result.stdout}\n${result.stderr}`, /STEP_C: deploying|firebase deploy --config/);
  assert.doesNotMatch(firebaseText, /deploy/);
});
