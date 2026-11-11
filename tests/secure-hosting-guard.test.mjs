import { test } from 'node:test';
import assert from 'node:assert/strict';
import { assertSecureTarget, assertPrivateWebConfig, latestRelease } from '../scripts/secure-hosting-guard.mjs';

const site = 'master-intelligence-5496f-lb';
const rc = { projects: { default: 'master-intelligence-5496f' }, targets: { 'master-intelligence-5496f': { hosting: { blitz: [site] } } } };
const config = { hosting: { target: 'blitz', public: '.firebase-blitz-private-shell' } };
const web = { firebase: {apiKey:'public-web-key',authDomain:'master-intelligence-5496f.firebaseapp.com',projectId:'master-intelligence-5496f',appId:'1:abc:web:xyz'},useEmulators:false};
const parse = (v) => assertPrivateWebConfig(`globalThis.BLITZ_SECURE_CONFIG = ${JSON.stringify(v)};\n`);
const release = { releases:[{name:`sites/${site}/channels/live/releases/123`,type:'DEPLOY',version:{name:`sites/${site}/versions/456`}}]};

test('private target is exact and rejects cross-site targets', () => {
  assert.doesNotThrow(() => assertSecureTarget(rc, config));
  assert.throws(() => assertSecureTarget(rc, {hosting:{target:'prep',public:'.firebase-blitz-private-shell'}}));
  assert.throws(() => assertSecureTarget(rc, {hosting:{target:'blitz',public:'.firebase-blitz-demo'}}));
  assert.throws(() => assertSecureTarget(rc, {hosting:{...config.hosting,rewrites:[{source:'**',function:'api'}]}}));
  assert.throws(() => assertSecureTarget({...rc, targets:{...rc.targets,other:{}}},config));
  assert.throws(() => assertSecureTarget(rc, {...config,firestore:{rules:'rules'}}));
});

test('built production shell rejects wrong project/emulator/extra secrets', () => {
  assert.equal(parse(web).firebase.projectId, 'master-intelligence-5496f');
  assert.throws(() => parse({...web,useEmulators:true}));
  assert.throws(() => parse({...web,firebase:{...web.firebase,projectId:'demo-blitz-secure'}}));
  assert.throws(() => parse({...web,firebase:{...web.firebase,authDomain:'attacker.example'}}));
  assert.throws(() => parse({...web,firebase:{...web.firebase,ownerUID:'secret'}}));
  assert.throws(() => parse({...web,firebase:{...web.firebase,apiKey:'REPLACE_ME'}}));
});

test('rollback baseline requires live-channel exact version', () => {
  assert.equal(latestRelease(JSON.stringify(release)).version, `sites/${site}/versions/456`);
  assert.throws(()=>latestRelease(JSON.stringify({releases:[]})));
  assert.throws(()=>latestRelease(JSON.stringify({releases:[{...release.releases[0],name:'sites/other/channels/live/releases/1'}]})));
  assert.throws(()=>latestRelease(JSON.stringify({releases:[{...release.releases[0],version:{name:'sites/other/versions/123'}}]})));
});
