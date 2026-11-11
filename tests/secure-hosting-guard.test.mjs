import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
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

function runDeploy(env) {
  const childEnv = { ...process.env };
  delete childEnv.CI;
  delete childEnv.GITHUB_ACTIONS;
  delete childEnv.DASHBOARD_PASSPHRASE;
  Object.assign(childEnv, env);
  return spawnSync('bash', ['scripts/deploy-secure-blitz.sh'], {
    env: childEnv, encoding: 'utf8', timeout: 10000,
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
    input: JSON.stringify(channel()), encoding: 'utf8',
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
    input: JSON.stringify({ releases: [channel().release], nextPageToken: 'next' }), encoding: 'utf8',
  });
  assert.notEqual(paged.status, 0);
  assert.match(paged.stderr, /not a paged list/);
  assert.equal(paged.stdout, '');
  const configured = spawnSync(process.execPath, ['scripts/secure-hosting-guard.mjs', '--assert-config'], {
    encoding: 'utf8',
  });
  assert.equal(configured.status, 0, configured.stderr);
  assert.match(configured.stdout, /hosting:blitz/);
});

test('secure deploy script can target only hosting:blitz and prints an exact clone rollback', () => {
  assert.equal(spawnSync('bash', ['-n', 'scripts/deploy-secure-blitz.sh'], { encoding: 'utf8' }).status, 0);
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
});

test('secure deploy refuses CI, a missing opt-in, a passphrase, and the wrong commit', () => {
  const missing = runDeploy({});
  assert.notEqual(missing.status, 0);
  assert.match(missing.stderr, /Explicit Step C opt-in is required/);
  const ci = spawnSync('bash', ['scripts/deploy-secure-blitz.sh'], {
    env: { ...process.env, CI: 'true', BLITZ_APPROVE_SECURE_SHELL_DEPLOY: 'YES' },
    encoding: 'utf8',
    timeout: 10000,
  });
  assert.notEqual(ci.status, 0);
  assert.match(ci.stderr, /Never deploy from CI/);
  assert.doesNotMatch(`${ci.stdout}\n${ci.stderr}`, /STEP_C: deploying|firebase deploy --config/);
  const secret = 'synthetic-review-passphrase';
  const passphrase = runDeploy({ BLITZ_APPROVE_SECURE_SHELL_DEPLOY: 'YES', DASHBOARD_PASSPHRASE: secret });
  assert.notEqual(passphrase.status, 0);
  assert.match(passphrase.stderr, /No campaign passphrase/);
  assert.doesNotMatch(`${passphrase.stdout}\n${passphrase.stderr}`, new RegExp(secret));
  const wrong = runDeploy({ BLITZ_APPROVE_SECURE_SHELL_DEPLOY: 'YES', BLITZ_APPROVED_COMMIT: '0000000000000000000000000000000000000000' });
  assert.notEqual(wrong.status, 0);
  assert.match(wrong.stderr, /not the approved commit/);
  assert.doesNotMatch(`${wrong.stdout}\n${wrong.stderr}`, /STEP_C: deploying|firebase deploy --config/);
});
