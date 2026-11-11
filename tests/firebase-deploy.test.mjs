import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';

const script = readFileSync('scripts/deploy-firebase-demo.sh', 'utf8');

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
  assert.match(script, /hosting:sites:list/);
  assert.match(script, /firebase deploy --only "hosting:\$TARGET" --project "\$PROJECT" --non-interactive/);
  assert.doesNotMatch(script, /firebase deploy\s*(?:\n|$)|--only hosting(?:\s|$)|firebase deploy --only firestore/);
  assert.doesNotMatch(script, /docs\/data\.enc\.json|firebase\.secure\.json|firebase\.firestore\.json/);
});
