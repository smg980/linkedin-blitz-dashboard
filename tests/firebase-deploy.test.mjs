import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import {
  PROJECT, SITE, assertHostingConfig, assertExactSiteListed, parseSiteList,
} from '../scripts/blitz-hosting-guard.mjs';

const script = readFileSync('scripts/deploy-firebase-demo.sh', 'utf8');
const site = id => ({ name: `projects/${PROJECT}/sites/${id}`, defaultUrl: `https://${id}.web.app` });
const listed = ids => JSON.stringify({ status: 'success', result: { sites: ids.map(site) } });

test('synthetic Blitz deployment refuses to run without independent approval', () => {
  const env = { ...process.env };
  delete env.BLITZ_APPROVE_SYNTHETIC_DEPLOY;
  const result = spawnSync('bash', ['scripts/deploy-firebase-demo.sh'], {
    env, encoding: 'utf8', timeout: 10000,
  });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /separate explicit synthetic-only Blitz deployment approval/);
});

test('synthetic Blitz deployment is site-scoped and cannot publish real campaign data', () => {
  assert.match(script, /PROJECT="master-intelligence-5496f"/);
  assert.match(script, /SITE="master-intelligence-5496f-lb"/);
  assert.match(script, /TARGET="blitz"/);
  assert.match(script, /BLITZ_APPROVE_SYNTHETIC_DEPLOY/);
  assert.match(script, /DASHBOARD_PASSPHRASE/);
  assert.match(script, /npm test/);
  assert.match(script, /npm run verify:bundle/);
  assert.match(script, /npm run build:firebase-demo/);
  assert.match(script, /npm run verify:firebase-demo/);
  assert.match(script, /hosting:sites:list --project "\$PROJECT" --json --non-interactive/);
  assert.match(script, /firebase deploy --only "hosting:\$TARGET" --project "\$PROJECT" --non-interactive/);
  assert.match(script, /cannot run in CI/);
  assert.doesNotMatch(script, /firebase deploy\s*(?:\n|$)|--only hosting(?:\s|$)|firebase deploy --only firestore|hosting:sites:create|hosting:disable|sites:delete/);
  assert.doesNotMatch(script, /docs\/data\.enc\.json|firebase\.secure\.json|firebase\.firestore\.json/);
});

test('synthetic Blitz deployment cannot run from CI even with the approval flag', () => {
  const env = { ...process.env, BLITZ_APPROVE_SYNTHETIC_DEPLOY: 'YES', GITHUB_ACTIONS: 'true' };
  delete env.DASHBOARD_PASSPHRASE;
  const result = spawnSync('bash', ['scripts/deploy-firebase-demo.sh'], {
    env, encoding: 'utf8', timeout: 5000,
  });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /cannot run in CI/);
  assert.doesNotMatch(`${result.stdout}\n${result.stderr}`, /Deploying synthetic-only|firebase deploy/);
});

test('committed Firebase config targets only the dedicated Blitz site', () => {
  const rc = JSON.parse(readFileSync('.firebaserc', 'utf8'));
  const config = JSON.parse(readFileSync('firebase.json', 'utf8'));
  assert.doesNotThrow(() => assertHostingConfig(rc, config));
  const drifted = structuredClone(rc);
  drifted.targets[PROJECT].hosting.blitz = ['master-intelligence-5496f-prep'];
  assert.throws(() => assertHostingConfig(drifted, config), /dedicated Blitz site/);
  const extra = structuredClone(rc);
  extra.targets[PROJECT].hosting.app = ['master-intelligence-5496f-app'];
  assert.throws(() => assertHostingConfig(extra, config), /only the Blitz hosting target|dedicated Blitz site/);
  assert.throws(() => assertHostingConfig(rc, { ...config, firestore: { rules: 'firestore.rules' } }), /only hosting/);
});

test('site list acceptance requires the exact Blitz site id among neighboring sites', () => {
  const neighbors = ['master-intelligence-5496f', 'master-intelligence-5496f-prep', 'master-intelligence-5496f-app'];
  assert.deepEqual(parseSiteList(listed([...neighbors, SITE])), [...neighbors, SITE]);
  assert.doesNotThrow(() => assertExactSiteListed(listed([...neighbors, SITE])));
  assert.throws(() => assertExactSiteListed(listed(neighbors)), /absent/);
  assert.throws(() => assertExactSiteListed(listed([...neighbors, `${SITE}-extra`])), /absent/);
  assert.throws(() => assertExactSiteListed(listed([...neighbors, SITE]), 'master-intelligence-5496f-prep'), /other than the dedicated/);
  assert.throws(() => parseSiteList(JSON.stringify({ status: 'error', result: { sites: [] } })), /failed/);
});
