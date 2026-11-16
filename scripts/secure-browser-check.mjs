import fs from 'node:fs/promises';
import http from 'node:http';
import path from 'node:path';
import puppeteer from 'puppeteer-core';

const DESKTOP_UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';
const IPHONE_UA = 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1';
const NAMES = ['Example Ada', 'Example Ben', 'Example Cy', 'Example Di'];
const VIEWPORT = { width: 390, height: 844, isMobile: true, hasTouch: true, deviceScaleFactor: 1 };

function chromePath() {
  const candidates = [
    process.env.CHROME_PATH,
    '/usr/bin/google-chrome',
    '/usr/bin/google-chrome-stable',
    '/usr/bin/chromium',
    '/usr/bin/chromium-browser',
  ].filter(Boolean);
  return candidates;
}

async function findChrome() {
  for (const candidate of chromePath()) {
    try {
      await fs.access(candidate);
      return candidate;
    } catch { /* try the next browser */ }
  }
  throw new Error('Google Chrome is required for the secure shell browser check');
}

function contentType(file) {
  const ext = path.extname(file);
  return {
    '.html': 'text/html; charset=utf-8',
    '.js': 'text/javascript; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.woff2': 'font/woff2',
    '.png': 'image/png',
    '.webp': 'image/webp',
    '.ico': 'image/x-icon',
  }[ext] || 'application/octet-stream';
}

function serve(root) {
  const base = path.resolve(root);
  const server = http.createServer((req, res) => {
    const url = new URL(req.url || '/', 'http://127.0.0.1');
    const rel = decodeURIComponent(url.pathname).replace(/^\/+/, '') || 'index.html';
    const file = path.resolve(base, rel);
    if (file !== base && !file.startsWith(base + path.sep)) {
      res.writeHead(403);
      res.end();
      return;
    }
    fs.readFile(file).then((body) => {
      res.writeHead(200, { 'Content-Type': contentType(file), 'Cache-Control': 'no-store' });
      res.end(body);
    }).catch(() => {
      res.writeHead(404);
      res.end();
    });
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server)));
}

async function assertNoOverflow(page, label) {
  await page.evaluate(() => document.fonts?.ready);
  const metrics = await page.evaluate(() => ({
    client: document.documentElement.clientWidth,
    scroll: document.documentElement.scrollWidth,
    body: document.body.scrollWidth,
  }));
  if (metrics.scroll - metrics.client > 1 || metrics.body - metrics.client > 1) {
    throw new Error(`${label} overflows horizontally at iPhone width: ${JSON.stringify(metrics)}`);
  }
}

async function shot(page, dir, name) {
  await fs.mkdir(dir, { recursive: true });
  await page.screenshot({ path: path.join(dir, name), fullPage: true });
}

async function storageLeak(page, markers) {
  const blob = await page.evaluate(async () => {
    const dump = { local: { ...localStorage }, session: { ...sessionStorage }, idb: '' };
    const dbs = indexedDB.databases ? await indexedDB.databases() : [];
    const parts = [];
    for (const dbInfo of dbs) {
      if (!dbInfo.name) continue;
      const rows = await new Promise((resolve) => {
        const open = indexedDB.open(dbInfo.name);
        open.onerror = () => resolve([]);
        open.onsuccess = () => {
          const db = open.result;
          const names = [...db.objectStoreNames];
          if (!names.length) {
            db.close();
            resolve([]);
            return;
          }
          const tx = db.transaction(names, 'readonly');
          const collected = [];
          let pending = names.length;
          for (const name of names) {
            const req = tx.objectStore(name).getAll();
            req.onsuccess = () => {
              collected.push(req.result);
              pending -= 1;
              if (!pending) {
                db.close();
                resolve(collected);
              }
            };
            req.onerror = () => {
              pending -= 1;
              if (!pending) {
                db.close();
                resolve(collected);
              }
            };
          }
        };
      });
      parts.push(JSON.stringify(rows));
    }
    dump.idb = parts.join('\n');
    return JSON.stringify(dump);
  });
  for (const marker of markers) {
    if (blob.includes(marker)) throw new Error('Plaintext or passphrase was stored in the browser');
  }
}

function waitForPopup(page) {
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve(null), 20000);
    page.once('popup', (popup) => {
      clearTimeout(timer);
      resolve(popup);
    });
  });
}

async function completeEmulatorAccount(target, email) {
  await target.waitForFunction(() => document.readyState === 'complete' && document.querySelector('.js-reuse-account, #add-account-button'), { timeout: 20000 });
  const clicked = await target.evaluate((wanted) => {
    const item = [...document.querySelectorAll('.js-reuse-account')].find((el) => el.textContent.includes(wanted));
    if (!item) return false;
    item.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true }));
    return true;
  }, email);
  if (!clicked) {
    const text = await target.evaluate(() => (document.body?.innerText || '').slice(0, 400));
    throw new Error('Auth emulator did not list the synthetic account. ' + text);
  }
}

async function prepare(page, url, userAgent) {
  await page.setUserAgent(userAgent);
  await page.setViewport(VIEWPORT);
  const viewport = page.viewport();
  if (viewport.width !== 390 || viewport.height !== 844) throw new Error('Browser viewport is not 390x844');
  await page.goto(url, { waitUntil: 'networkidle0', timeout: 30000 });
  await page.waitForSelector('body[data-booted="yes"]', { timeout: 20000 });
}

export async function checkSecureShell({ shellDir, passphrase, artifactsDir, ownerEmail, intruderEmail }) {
  const server = await serve(shellDir);
  const browser = await puppeteer.launch({
    executablePath: await findChrome(),
    headless: true,
    args: [
      '--no-sandbox',
      '--disable-dev-shm-usage',
      '--disable-popup-blocking',
      '--disable-gpu',
      '--disable-features=ThirdPartyStoragePartitioning,TrackingProtection3pcd,BlockThirdPartyCookies',
    ],
  });
  const firestoreRequests = [];
  const states = [];
  try {
    const address = server.address();
    const url = `http://127.0.0.1:${address.port}/`;
    const page = await browser.newPage();
    page.on('request', (req) => {
      const target = req.url();
      if (req.method() === 'OPTIONS' || req.method() === 'HEAD') return;
      if (target.includes('/documents') || target.includes(':runQuery') || target.includes(':commit') || target.includes(':batchWrite') || target.includes('firestore.googleapis.com')) {
        firestoreRequests.push({ method: req.method(), url: target.split('?')[0] });
      }
    });
    await prepare(page, url, DESKTOP_UA);
    if (page.viewport().width !== 390) throw new Error('Signed-out viewport drifted');
    await assertNoOverflow(page, 'signed-out');
    await shot(page, artifactsDir, 'secure-state-signed-out.png');
    states.push('signed-out');

    const logs = [];
    page.on('console', (msg) => { if (msg.type() === 'error') logs.push(msg.text()); });
    page.on('pageerror', (err) => logs.push(err.message));
    const popupPromise = waitForPopup(page);
    await page.click('[data-action="sign-in"]');
    const flash = await page.evaluate(() => document.body.dataset.state).catch(() => '');
    if (flash !== 'signing-in') {
      const diag = await page.evaluate(() => ({
        state: document.body.dataset.state,
        message: document.getElementById('gate-message')?.textContent || '',
        href: location.href,
      })).catch(() => ({ href: page.url() }));
      throw new Error('Did not enter signing-in ' + JSON.stringify({ diag, logs }));
    }
    await assertNoOverflow(page, 'signing-in');
    await shot(page, artifactsDir, 'secure-state-signing-in.png');
    states.push('signing-in');
    const popup = await Promise.race([
      popupPromise,
      page.waitForFunction(() => location.pathname.includes('/emulator/auth/handler'), { timeout: 20000 }).then(() => null).catch(() => null),
    ]);
    await completeEmulatorAccount(popup || page, intruderEmail);
    await page.waitForSelector('body[data-state="not-authorized"]', { timeout: 30000 });
    const signOut = await page.$('#lock [data-action="sign-out"]');
    if (!signOut) throw new Error('Not-authorized screen is missing Sign out');
    await assertNoOverflow(page, 'not-authorized');
    await shot(page, artifactsDir, 'secure-state-not-authorized.png');
    states.push('not-authorized');
    await page.click('#lock [data-action="sign-out"]');
    await page.waitForSelector('body[data-state="signed-out"]', { timeout: 15000 });

    const ownerPopupPromise = waitForPopup(page);
    await page.click('[data-action="sign-in"]');
    const ownerPopup = await Promise.race([
      ownerPopupPromise,
      page.waitForFunction(() => location.pathname.includes('/emulator/auth/handler'), { timeout: 20000 }).then(() => null).catch(() => null),
    ]);
    await completeEmulatorAccount(ownerPopup || page, ownerEmail);
    await page.waitForSelector('body[data-state="locked"]', { timeout: 30000 });
    await assertNoOverflow(page, 'locked');
    await shot(page, artifactsDir, 'secure-state-locked.png');
    states.push('locked');

    await page.$eval('#pass', (el) => { el.value = 'not-the-synthetic-passphrase'; });
    await page.click('#unlock-btn');
    await page.waitForSelector('body[data-state="wrong-passphrase"]', { timeout: 60000 });
    await assertNoOverflow(page, 'wrong-passphrase');
    await shot(page, artifactsDir, 'secure-state-wrong-passphrase.png');
    states.push('wrong-passphrase');

    await page.$eval('#pass', (el, value) => { el.value = value; }, passphrase);
    await page.click('#unlock-btn');
    await page.waitForSelector('body[data-state="unlocked"]', { timeout: 60000 });
    const visible = await page.evaluate((names) => {
      const text = document.body.innerText;
      return Object.fromEntries(names.map((name) => [name, text.includes(name)]));
    }, NAMES);
    if (!NAMES.every((name) => visible[name])) throw new Error('Unlocked shell did not show the fictional contacts');
    const leakedPass = await page.evaluate((secret) => document.documentElement.innerHTML.includes(secret), passphrase);
    if (leakedPass) throw new Error('Passphrase remained in the page');
    await assertNoOverflow(page, 'unlocked');
    await shot(page, artifactsDir, 'secure-state-unlocked.png');
    states.push('unlocked');

    await page.click('[data-action="lock"]');
    await page.waitForSelector('body[data-state="locked"]', { timeout: 10000 });
    const afterLock = await page.content();
    if (NAMES.some((name) => afterLock.includes(name)) || afterLock.includes(passphrase)) {
      throw new Error('Lock left decrypted contact names in the DOM');
    }
    await assertNoOverflow(page, 'locked-after-lock');
    await shot(page, artifactsDir, 'secure-state-locked-after-lock.png');
    await storageLeak(page, [passphrase, ...NAMES, 'EXAMPLE Acme', 'EXAMPLE Globex']);
    await page.click('#lock [data-action="sign-out"]');
    await page.waitForSelector('body[data-state="signed-out"]', { timeout: 15000 });
    const afterSignOut = await page.content();
    if (NAMES.some((name) => afterSignOut.includes(name))) throw new Error('Sign out left decrypted contact names in the DOM');
    await storageLeak(page, [passphrase, ...NAMES]);

    for (const req of firestoreRequests) {
      const pathname = new URL(req.url).pathname;
      if (req.method !== 'GET' || !/\/documents\/blitzOwners\/[^/]+\/campaign\/current$/.test(pathname)) {
        throw new Error('Client made a Firestore request other than a single-document get: ' + req.method + ' ' + req.url);
      }
    }
    if (firestoreRequests.length < 2) throw new Error('Signed-in shell did not read its private document');

    const redirect = await browser.createBrowserContext();
    const iphone = await redirect.newPage();
    await prepare(iphone, url, IPHONE_UA);
    await iphone.click('[data-action="sign-in"]');
    await iphone.waitForFunction(() => location.pathname.includes('/emulator/auth/handler'), { timeout: 20000 });
    await completeEmulatorAccount(iphone, ownerEmail);
    try {
      await iphone.waitForSelector('body[data-state="locked"]', { timeout: 30000 });
    } catch (error) {
      const info = await iphone.evaluate(() => ({
        href: location.href,
        state: document.body?.dataset?.state || '',
        text: (document.body?.innerText || '').slice(0, 400),
      })).catch(() => ({ href: iphone.url() }));
      throw new Error('iPhone redirect did not return to the locked shell: ' + JSON.stringify(info));
    }
    await assertNoOverflow(iphone, 'iphone-redirect-locked');
    if (iphone.viewport().width !== 390 || iphone.viewport().height !== 844) throw new Error('iPhone redirect viewport drifted');
    states.push('iphone-redirect');
    await redirect.close();
    return { states };
  } finally {
    await browser.close();
    await new Promise((resolve) => server.close(resolve));
  }
}
