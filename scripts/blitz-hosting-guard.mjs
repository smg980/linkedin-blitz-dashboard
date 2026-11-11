// Fail-closed checks for the synthetic LinkedIn Blitz Hosting release.
// This module never calls Firebase and never reads campaign ciphertext.
import fs from 'node:fs';

export const PROJECT = 'master-intelligence-5496f';
export const SITE = 'master-intelligence-5496f-lb';
export const TARGET = 'blitz';

const FORBIDDEN_CONFIG_KEYS = ['firestore', 'functions', 'storage', 'database', 'emulators'];

export function assertHostingConfig(rc, config) {
  if (!rc || rc.projects?.default !== PROJECT) {
    throw new Error('Firebase default project must be the shared MASTER project only');
  }
  const projectTargets = rc.targets?.[PROJECT];
  const hosting = projectTargets?.hosting;
  if (!projectTargets || Object.keys(projectTargets).length !== 1 || Object.keys(rc.targets).length !== 1) {
    throw new Error('Firebase targets must contain only the Blitz hosting target');
  }
  if (JSON.stringify(hosting) !== JSON.stringify({ [TARGET]: [SITE] })) {
    throw new Error('Firebase blitz target must map only to the dedicated Blitz site');
  }
  if (!config || JSON.stringify(Object.keys(config)) !== JSON.stringify(['hosting'])) {
    throw new Error('firebase.json must contain only hosting');
  }
  if (Array.isArray(config.hosting) || config.hosting?.target !== TARGET || config.hosting?.public !== '.firebase-blitz-demo') {
    throw new Error('firebase.json hosting must target only blitz and the synthetic output directory');
  }
  if (config.hosting.rewrites !== undefined) throw new Error('Blitz hosting config must not rewrite to another service');
  for (const key of FORBIDDEN_CONFIG_KEYS) {
    if (config[key] != null) throw new Error('Unexpected Firebase product in config: ' + key);
  }
}

export function parseSiteList(text) {
  const start = String(text).indexOf('{');
  const end = String(text).lastIndexOf('}');
  if (start < 0 || end <= start) throw new Error('Firebase site list was not JSON');
  const parsed = JSON.parse(String(text).slice(start, end + 1));
  if (parsed.status && parsed.status !== 'success') throw new Error('Firebase site list failed');
  const sites = parsed.result?.sites || parsed.sites;
  if (!Array.isArray(sites)) throw new Error('Firebase site list has no sites array');
  return sites.map(site => {
    const parts = String(site?.name || '').split('/').filter(Boolean);
    if (parts.length < 4 || parts[0] !== 'projects' || parts[2] !== 'sites' || parts[1] !== PROJECT) {
      throw new Error('Unexpected site resource name');
    }
    return parts[3];
  });
}

export function assertExactSiteListed(text, siteId = SITE) {
  if (siteId !== SITE) throw new Error('Refusing to look for any site other than the dedicated Blitz site');
  const ids = parseSiteList(text);
  if (ids.filter(id => id === SITE).length !== 1) {
    throw new Error('Dedicated Blitz Hosting site is absent from the exact site list');
  }
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

if (process.argv[1] && process.argv[1].endsWith('blitz-hosting-guard.mjs')) {
  try {
    if (process.argv.includes('--assert-config')) {
      assertHostingConfig(readJson('.firebaserc'), readJson('firebase.json'));
      console.log('PASS: release targets only the isolated LinkedIn Blitz Hosting site.');
    }
    const siteFlag = process.argv.indexOf('--require-site');
    if (siteFlag !== -1) {
      assertExactSiteListed(fs.readFileSync(0, 'utf8'), process.argv[siteFlag + 1]);
      console.log('PASS: dedicated Blitz Hosting site is present. No site was created.');
    }
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
