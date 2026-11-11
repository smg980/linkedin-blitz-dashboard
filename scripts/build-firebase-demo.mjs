#!/usr/bin/env node
// Produce an isolated Firebase Hosting preview from synthetic contacts only.
// NEVER copy docs/data.enc.json or real campaign content into this output.
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DOCS = path.join(ROOT, 'docs');
const OUT = path.join(ROOT, '.firebase-blitz-demo');
const TEMP = path.join(ROOT, '.firebase-blitz-demo-tmp');
export const DEMO_PASSPHRASE = 'SYNTHETIC-BLITZ-DEMO-ONLY-2026';
const ASSETS = [
  'index.html', 'app.js', 'theme.css', 'blitz.css', 'favicon.ico',
  'fonts/DMSans-latin.woff2', 'fonts/Manrope-latin.woff2',
  'img/apple-touch-icon.png', 'img/favicon-32.png',
  'img/logo-header.png', 'img/logo-header.webp',
  'img/logo-lock.png', 'img/logo-lock.webp',
];

async function listFiles(root, relative = '') {
  const entries = await fs.readdir(path.join(root, relative), { withFileTypes: true });
  const paths = [];
  for (const entry of entries) {
    const file = path.posix.join(relative, entry.name);
    if (entry.isDirectory()) paths.push(...await listFiles(root, file));
    else if (entry.isFile()) paths.push(file);
    else throw new Error('Unsupported file type in Firebase output: ' + file);
  }
  return paths.sort();
}

async function run() {
  if (process.env.DASHBOARD_PASSPHRASE) {
    throw new Error('Do not run the synthetic Firebase builder with a real dashboard passphrase in the environment');
  }
  await fs.rm(TEMP, { recursive: true, force: true });
  await fs.mkdir(TEMP, { recursive: true });
  try {
    for (const asset of ASSETS) {
      const outputFile = path.join(TEMP, asset);
      await fs.mkdir(path.dirname(outputFile), { recursive: true });
      await fs.copyFile(path.join(DOCS, asset), outputFile);
    }
    let html = await fs.readFile(path.join(TEMP, 'index.html'), 'utf8');
    if (!html.includes('<h1>LinkedIn Blitz</h1>')) throw new Error('Unexpected lock-screen markup');
    html = html
      .replace('<title>LinkedIn Blitz</title>', '<title>SYNTHETIC DEMO — LinkedIn Blitz</title>')
      .replace('<h1>LinkedIn Blitz</h1>', '<h1>LinkedIn Blitz — Synthetic Demo</h1>')
      .replace(
        '<p class="muted">This dashboard is encrypted. Enter your passphrase to unlock.</p>',
        '<p class="muted">SYNTHETIC DATA ONLY. No customer contacts or live outreach. Use the demo passphrase below.</p><p class="fine">Demo passphrase: <code>' + DEMO_PASSPHRASE + '</code></p>'
      );
    await fs.writeFile(path.join(TEMP, 'index.html'), html);

    const result = spawnSync(process.execPath, [path.join(ROOT, 'scripts', 'build.mjs'), '--example'], {
      cwd: ROOT,
      env: { ...process.env, DASHBOARD_PASSPHRASE: DEMO_PASSPHRASE, BLITZ_OUTPUT_DIR: TEMP, BLITZ_DIR: path.join(ROOT, 'does-not-exist-private-sources') },
      encoding: 'utf8'
    });
    if (result.status !== 0) throw new Error('Synthetic encryption build failed: ' + (result.stderr || result.stdout).slice(0,1500));

    const content = JSON.parse(await fs.readFile(path.join(TEMP, 'data.enc.json'), 'utf8'));
    if (content.alg !== 'AES-256-GCM' || content.iterations !== 600000 || Object.keys(content).length !== 7) {
      throw new Error('Synthetic ciphertext did not pass the expected envelope check');
    }
    const files = await listFiles(TEMP);
    const allowed = [...ASSETS, 'data.enc.json'].sort();
    if (JSON.stringify(files) !== JSON.stringify(allowed)) throw new Error('Unexpected file in synthetic Hosting build');
    await fs.rm(OUT, { recursive: true, force: true });
    await fs.rename(TEMP, OUT);
    console.log('Synthetic Firebase preview prepared. Only example data; no GitHub Pages output changed.');
  } catch (error) {
    await fs.rm(TEMP, { recursive: true, force: true });
    throw error;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  run().catch(error => { console.error(error.message); process.exitCode = 1; });
}
