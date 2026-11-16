// F1 regression: a pending unlock must never outlive the sign-in, session and
// envelope it started under. Runs the real secure/shell.js in Chromium with the
// Firebase SDK and the Firestore read replaced by in-page stubs, and holds
// crypto.subtle.decrypt open so each race is reproduced deterministically.
// Synthetic, fictional data only. No emulator, no network.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import esbuild from 'esbuild';
import puppeteer from 'puppeteer-core';
import { encryptEnvelope } from '../secure/envelope.mjs';
import { spawnSync } from 'node:child_process';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const OWNER_A = 'synthetic-race-owner-a';
const OWNER_B = 'synthetic-race-owner-b';
const PASS_A = 'synthetic-race-passphrase-alpha';
const PASS_B = 'synthetic-race-passphrase-bravo';
const ALPHA = 'Race Alpha Fictional';
const BRAVO = 'Race Bravo Fictional';
const LOCAL_CSP = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'";

const STUB_APP = `export function initializeApp(options) { return { options }; }\n`;
const STUB_AUTH = `
const listeners = new Set();
const auth = { currentUser: null };
let popupUid = '';
function user(uid) { return { uid, getIdToken: async () => 'synthetic-token-' + uid }; }
function notify() { const current = auth.currentUser; for (const cb of [...listeners]) cb(current); }
globalThis.__raceAuth = {
  setPopupUser(uid) { popupUid = uid; },
  switchTo(uid) { auth.currentUser = user(uid); notify(); },
  dropSession() { auth.currentUser = null; notify(); },
};
export const browserSessionPersistence = { type: 'SESSION' };
export const inMemoryPersistence = { type: 'NONE' };
export function getAuth() { return auth; }
export function connectAuthEmulator() {}
export async function setPersistence() {}
export async function getRedirectResult() { return null; }
export async function signInWithRedirect() { throw Object.assign(new Error('redirect disabled in stub'), { code: 'auth/operation-not-supported-in-this-environment' }); }
export async function signInWithPopup() { auth.currentUser = user(popupUid); notify(); return { user: auth.currentUser }; }
export async function signOut() { auth.currentUser = null; notify(); }
export function onAuthStateChanged(_auth, cb) { listeners.add(cb); queueMicrotask(() => cb(auth.currentUser)); return () => listeners.delete(cb); }
export class GoogleAuthProvider { setCustomParameters() {} }
`;
const STUB_FIRESTORE = `
export async function readPrivateDocument({ uid }) {
  const envelope = globalThis.__raceEnvelopes && globalThis.__raceEnvelopes[uid];
  return envelope ? { status: 'ok', envelope: JSON.parse(JSON.stringify(envelope)) } : { status: 'missing' };
}
`;

// Installed before any page script. Each decrypt call can be held until the
// test releases it, which pins the exact interleaving under test.
function installGate() {
  const original = crypto.subtle.decrypt.bind(crypto.subtle);
  const gate = { armed: false, entered: 0, settled: 0, releases: [] };
  window.__gate = gate;
  crypto.subtle.decrypt = async (...args) => {
    if (gate.armed) {
      gate.entered += 1;
      await new Promise((resolve) => { gate.releases.push(resolve); });
    }
    try {
      return await original(...args);
    } finally {
      gate.settled += 1;
    }
  };
}

// Chrome or Chromium is required; a missing browser fails the test rather than skipping it.
function chromePath() {
  const candidates = process.env.CHROME_PATH ? [process.env.CHROME_PATH] : [
    '/usr/bin/google-chrome',
    '/usr/bin/google-chrome-stable',
    '/usr/bin/chromium',
    '/usr/bin/chromium-browser',
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  ];
  for (const candidate of candidates) {
    const probe = spawnSync(candidate, ['--version'], { encoding: 'utf8', timeout: 5000, killSignal: 'SIGKILL' });
    if (!probe.error && probe.status === 0 && /(?:Google Chrome|Chromium)\b/.test(`${probe.stdout}${probe.stderr}`)) return candidate;
  }
  throw new Error('Chrome or Chromium is required for the unlock race regression. Set CHROME_PATH.');
}

let work;
let server;
let browser;
let envelopes;

function serve(dir) {
  const files = new Map([
    ['/', ['index.html', 'text/html; charset=utf-8']],
    ['/index.html', ['index.html', 'text/html; charset=utf-8']],
    ['/config.js', ['config.js', 'text/javascript; charset=utf-8']],
    ['/shell.js', ['shell.js', 'text/javascript; charset=utf-8']],
  ]);
  const srv = http.createServer((req, res) => {
    const entry = files.get(new URL(req.url || '/', 'http://127.0.0.1').pathname);
    if (!entry) {
      res.writeHead(404);
      res.end();
      return;
    }
    fs.readFile(path.join(dir, entry[0])).then((body) => {
      res.writeHead(200, { 'Content-Type': entry[1], 'Cache-Control': 'no-store' });
      res.end(body);
    }, () => {
      res.writeHead(500);
      res.end();
    });
  });
  return new Promise((resolve) => srv.listen(0, '127.0.0.1', () => resolve(srv)));
}

before(async () => {
  work = await fs.mkdtemp(path.join(os.tmpdir(), 'blitz-unlock-race-'));
  const stubs = path.join(work, 'stubs');
  const site = path.join(work, 'site');
  await fs.mkdir(stubs);
  await fs.mkdir(site);
  await fs.writeFile(path.join(stubs, 'app.mjs'), STUB_APP);
  await fs.writeFile(path.join(stubs, 'auth.mjs'), STUB_AUTH);
  await fs.writeFile(path.join(stubs, 'firestore-get.mjs'), STUB_FIRESTORE);
  await esbuild.build({
    absWorkingDir: root,
    entryPoints: [path.join(root, 'secure', 'shell.js')],
    bundle: true,
    format: 'iife',
    platform: 'browser',
    target: 'es2022',
    outfile: path.join(site, 'shell.js'),
    legalComments: 'none',
    logLevel: 'silent',
    plugins: [{
      name: 'race-stubs',
      setup(build) {
        build.onResolve({ filter: /^firebase\/app$/ }, () => ({ path: path.join(stubs, 'app.mjs') }));
        build.onResolve({ filter: /^firebase\/auth$/ }, () => ({ path: path.join(stubs, 'auth.mjs') }));
        build.onResolve({ filter: /firestore-get\.mjs$/ }, () => ({ path: path.join(stubs, 'firestore-get.mjs') }));
      },
    }],
  });
  const html = await fs.readFile(path.join(root, 'secure', 'index.html'), 'utf8');
  await fs.writeFile(path.join(site, 'index.html'), html.replace('__BLITZ_CSP__', LOCAL_CSP));
  await fs.writeFile(path.join(site, 'config.js'), `globalThis.BLITZ_SECURE_CONFIG = ${JSON.stringify({
    firebase: { apiKey: 'synthetic-race-key', authDomain: 'race.invalid', projectId: 'demo-race', appId: 'synthetic-race-app' },
    useEmulators: false,
  })};\n`);
  const payload = (name, account) => ({ example: true, campaign: { name: `${account} campaign` }, contacts: [{ account, contact: name, status: 'Draft Ready' }] });
  envelopes = {
    [OWNER_A]: await encryptEnvelope(payload(ALPHA, 'EXAMPLE Race Alpha Account'), PASS_A),
    [OWNER_B]: await encryptEnvelope(payload(BRAVO, 'EXAMPLE Race Bravo Account'), PASS_B),
  };
  server = await serve(site);
  browser = await puppeteer.launch({
    executablePath: chromePath(),
    headless: true,
    args: ['--no-sandbox', '--disable-dev-shm-usage', '--disable-gpu'],
  });
});

after(async () => {
  if (browser) {
    const proc = browser.process();
    await Promise.race([browser.close().catch(() => {}), new Promise((resolve) => setTimeout(resolve, 5000))]);
    if (proc && proc.exitCode == null) {
      try { proc.kill('SIGKILL'); } catch { /* already gone */ }
    }
  }
  if (server) {
    server.closeAllConnections?.();
    await new Promise((resolve) => server.close(() => resolve()));
  }
  if (work) await fs.rm(work, { recursive: true, force: true });
});

async function openShell() {
  const context = await browser.createBrowserContext();
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', (error) => errors.push(`pageerror: ${error.message}`));
  // Stylesheets and images are not served here, and Chrome warns that a meta CSP
  // cannot carry frame-ancestors. Every other console error fails the test.
  const benign = /^Failed to load resource: the server responded with a status of 404|'frame-ancestors' is ignored when delivered via a <meta> element/;
  page.on('console', (msg) => {
    if (msg.type() === 'error' && !benign.test(msg.text())) errors.push(`console: ${msg.text()}`);
  });
  await page.evaluateOnNewDocument(installGate);
  await page.evaluateOnNewDocument((value) => { globalThis.__raceEnvelopes = value; }, envelopes);
  const { port } = server.address();
  await page.goto(`http://127.0.0.1:${port}/`, { waitUntil: 'load' });
  await page.waitForSelector('body[data-booted="yes"]', { timeout: 20000 });
  return { page, context, errors };
}

async function state(page) {
  return page.evaluate(() => document.body.dataset.state);
}

async function waitState(page, wanted) {
  await page.waitForFunction((value) => document.body.dataset.state === value, { timeout: 30000 }, wanted);
}

async function signInPopup(page, uid) {
  await page.evaluate((value) => globalThis.__raceAuth.setPopupUser(value), uid);
  await page.click('[data-action="sign-in"]');
  await waitState(page, 'locked');
}

async function submitPassphrase(page, passphrase) {
  await page.$eval('#pass', (el, value) => { el.value = value; }, passphrase);
  await page.$eval('#unlock-form', (form) => form.requestSubmit());
}

async function arm(page) {
  await page.evaluate(() => { window.__gate.armed = true; });
}

async function disarm(page) {
  await page.evaluate(() => { window.__gate.armed = false; });
}

async function waitEntered(page, count) {
  await page.waitForFunction((n) => window.__gate.entered >= n, { timeout: 60000 }, count);
}

// Release one held decrypt and let every continuation it schedules finish.
async function release(page, index) {
  const settled = await page.evaluate(() => window.__gate.settled);
  await page.evaluate((i) => window.__gate.releases[i](), index);
  await page.waitForFunction((n) => window.__gate.settled > n, { timeout: 60000 }, settled);
  await page.evaluate(() => new Promise((resolve) => setTimeout(resolve, 100)));
}

async function visibleText(page) {
  return page.evaluate(() => `${document.body.innerText}\n${document.getElementById('private-view').innerHTML}`);
}

async function assertNoPlaintext(page, name) {
  const text = await visibleText(page);
  assert.equal(text.includes(name), false, `${name} reached the DOM`);
  assert.equal(await page.$eval('#private-view', (el) => el.childElementCount), 0);
  assert.equal(await page.$eval('#app', (el) => el.hidden), true);
}

test('sign-out while a decrypt is pending: the late success cannot unlock or render', { timeout: 120000 }, async () => {
  const { page, context, errors } = await openShell();
  try {
    await signInPopup(page, OWNER_A);
    await arm(page);
    await submitPassphrase(page, PASS_A);
    await waitEntered(page, 1);
    await page.click('#lock [data-action="sign-out"]');
    await waitState(page, 'signed-out');
    await release(page, 0);
    assert.equal(await state(page), 'signed-out');
    await assertNoPlaintext(page, ALPHA);
    assert.deepEqual(errors, []);
  } finally {
    await context.close();
  }
});

test('account change while a decrypt is pending: the old owner\'s plaintext never renders for the new one', { timeout: 120000 }, async () => {
  const { page, context, errors } = await openShell();
  try {
    await signInPopup(page, OWNER_A);
    await arm(page);
    await submitPassphrase(page, PASS_A);
    await waitEntered(page, 1);
    await page.evaluate((uid) => globalThis.__raceAuth.switchTo(uid), OWNER_B);
    await waitState(page, 'locked');
    await release(page, 0);
    assert.equal(await state(page), 'locked');
    await assertNoPlaintext(page, ALPHA);
    // The new owner's own unlock still works and shows only their data.
    await disarm(page);
    await submitPassphrase(page, PASS_B);
    await waitState(page, 'unlocked');
    const text = await visibleText(page);
    assert.equal(text.includes(BRAVO), true);
    assert.equal(text.includes(ALPHA), false);
    assert.deepEqual(errors, []);
  } finally {
    await context.close();
  }
});

test('account change while a wrong passphrase is pending: the late error does not mark the new session', { timeout: 120000 }, async () => {
  const { page, context, errors } = await openShell();
  try {
    await signInPopup(page, OWNER_A);
    await arm(page);
    await submitPassphrase(page, 'not-the-synthetic-race-passphrase');
    await waitEntered(page, 1);
    await page.evaluate((uid) => globalThis.__raceAuth.switchTo(uid), OWNER_B);
    await waitState(page, 'locked');
    await release(page, 0);
    assert.equal(await state(page), 'locked');
    assert.equal(await page.$eval('#gate-error', (el) => el.hidden), true);
    assert.equal(await page.$eval('#gate-error', (el) => el.textContent), '');
    assert.deepEqual(errors, []);
  } finally {
    await context.close();
  }
});

test('lock while a retry is pending: the late success cannot reopen the campaign', { timeout: 120000 }, async () => {
  const { page, context, errors } = await openShell();
  try {
    await signInPopup(page, OWNER_A);
    await submitPassphrase(page, 'not-the-synthetic-race-passphrase');
    await waitState(page, 'wrong-passphrase');
    await arm(page);
    await submitPassphrase(page, PASS_A);
    await waitEntered(page, 1);
    // The Lock control lives in the hidden app header; its handler still runs.
    await page.$eval('[data-action="lock"]', (button) => button.click());
    await waitState(page, 'locked');
    await release(page, 0);
    assert.equal(await state(page), 'locked');
    await assertNoPlaintext(page, ALPHA);
    assert.deepEqual(errors, []);
  } finally {
    await context.close();
  }
});

test('sign-out while a wrong passphrase is pending: the late error raises nothing and changes nothing', { timeout: 120000 }, async () => {
  const { page, context, errors } = await openShell();
  try {
    await signInPopup(page, OWNER_A);
    await arm(page);
    await submitPassphrase(page, 'not-the-synthetic-race-passphrase');
    await waitEntered(page, 1);
    await page.click('#lock [data-action="sign-out"]');
    await waitState(page, 'signed-out');
    await release(page, 0);
    assert.equal(await state(page), 'signed-out');
    assert.equal(await page.$eval('#gate-error', (el) => el.hidden), true);
    assert.equal(await page.$eval('[data-action="sign-in"]', (el) => el.hidden), false);
    assert.deepEqual(errors, []);
  } finally {
    await context.close();
  }
});

test('a stale handler does not touch the unlock button of the current attempt', { timeout: 180000 }, async () => {
  const { page, context, errors } = await openShell();
  try {
    await signInPopup(page, OWNER_A);
    await arm(page);
    await submitPassphrase(page, PASS_A);
    await waitEntered(page, 1);
    await page.click('#lock [data-action="sign-out"]');
    await waitState(page, 'signed-out');
    // Same owner signs in again and starts a fresh attempt against a fresh envelope.
    await signInPopup(page, OWNER_A);
    await submitPassphrase(page, PASS_A);
    await waitEntered(page, 2);
    const during = await page.$eval('#unlock-btn', (el) => ({ disabled: el.disabled, text: el.textContent }));
    assert.deepEqual(during, { disabled: true, text: 'Checking…' });
    await release(page, 0);
    assert.equal(await state(page), 'locked');
    assert.deepEqual(await page.$eval('#unlock-btn', (el) => ({ disabled: el.disabled, text: el.textContent })), during);
    await assertNoPlaintext(page, ALPHA);
    await release(page, 1);
    await waitState(page, 'unlocked');
    assert.equal((await visibleText(page)).includes(ALPHA), true);
    assert.deepEqual(await page.$eval('#unlock-btn', (el) => ({ disabled: el.disabled, text: el.textContent })), { disabled: false, text: 'Unlock' });
    assert.deepEqual(errors, []);
  } finally {
    await context.close();
  }
});
