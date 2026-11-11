#!/usr/bin/env node
// Build the private Firebase Hosting shell. Never copies docs/data.enc.json.
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import esbuild from 'esbuild';
import { emulatorCsp, productionCsp } from '../secure/csp.mjs';
import { SECURE_OUT, verifySecureShell } from './verify-secure-shell.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DOCS = path.join(ROOT, 'docs');
const ASSETS = [
  'theme.css',
  'blitz.css',
  'favicon.ico',
  'fonts/DMSans-latin.woff2',
  'fonts/Manrope-latin.woff2',
  'img/apple-touch-icon.png',
  'img/favicon-32.png',
  'img/logo-header.png',
  'img/logo-header.webp',
  'img/logo-lock.png',
  'img/logo-lock.webp',
];
const PLACEHOLDER = /REPLACE_ME|REPLACE_WITH|YOUR_|TODO|CHANGEME/i;
const REAL_PROJECT = 'master-intelligence-5496f';

function arg(name) {
  const index = process.argv.indexOf(name);
  return index === -1 ? null : process.argv[index + 1];
}

function parseHost(value, fallbackHost, fallbackPort) {
  if (!value) return { hostname: fallbackHost, port: fallbackPort };
  const trimmed = value.trim();
  const idx = trimmed.lastIndexOf(':');
  if (idx <= 0) throw new Error('Emulator host must include a port');
  return { hostname: trimmed.slice(0, idx), port: Number(trimmed.slice(idx + 1)) };
}

function assertWebConfig(firebase) {
  const required = ['apiKey', 'authDomain', 'projectId', 'appId'];
  for (const key of required) {
    if (typeof firebase?.[key] !== 'string' || !firebase[key].trim()) throw new Error('Firebase web config is missing ' + key);
  }
  if (PLACEHOLDER.test(JSON.stringify(firebase))) throw new Error('Firebase web config still contains placeholders');
  const extra = Object.keys(firebase).filter((key) => !required.includes(key));
  if (extra.length) throw new Error('Firebase web config has unexpected fields');
}

export async function loadShellConfig(options = {}) {
  const emulator = options.emulator ?? process.argv.includes('--emulator');
  if (process.env.DASHBOARD_PASSPHRASE) throw new Error('Refusing to build the secure shell while DASHBOARD_PASSPHRASE is set');
  if (emulator) {
    const auth = parseHost(process.env.FIREBASE_AUTH_EMULATOR_HOST, '127.0.0.1', 9099);
    const firestore = parseHost(process.env.FIRESTORE_EMULATOR_HOST, '127.0.0.1', 8080);
    if (!['127.0.0.1', 'localhost'].includes(auth.hostname) || !['127.0.0.1', 'localhost'].includes(firestore.hostname)) {
      throw new Error('Emulator shell can only point at loopback');
    }
    return {
      firebase: {
        apiKey: 'emulator-placeholder-not-a-real-key',
        authDomain: 'localhost',
        projectId: 'demo-blitz-secure',
        appId: 'emulator-placeholder-not-a-real-app',
      },
      useEmulators: true,
      emulators: {
        authHost: auth.hostname,
        authPort: auth.port,
        firestoreHost: firestore.hostname,
        firestorePort: firestore.port,
      },
    };
  }
  const configPath = options.configPath || arg('--config') || path.join(ROOT, 'secure-config.local.json');
  let parsed;
  try {
    parsed = JSON.parse(await fs.readFile(configPath, 'utf8'));
  } catch {
    throw new Error('Secure shell config is missing. Copy secure-config.example.json to secure-config.local.json or pass --emulator');
  }
  if (parsed.useEmulators) throw new Error('Local secure config cannot enable emulators. Use --emulator for the local shell');
  assertWebConfig(parsed.firebase);
  if (parsed.firebase.projectId === REAL_PROJECT && parsed.firebase.apiKey.startsWith('emulator-placeholder')) {
    throw new Error('Refusing a placeholder key for the real project id');
  }
  return { firebase: parsed.firebase, useEmulators: false };
}

function cspFor(config) {
  if (!config.useEmulators) return productionCsp();
  return emulatorCsp({
    authOrigin: `http://${config.emulators.authHost}:${config.emulators.authPort}`,
    firestoreOrigin: `http://${config.emulators.firestoreHost}:${config.emulators.firestorePort}`,
  });
}

export async function buildSecureShell(options = {}) {
  const config = await loadShellConfig(options);
  const out = options.out || (arg('--out') ? path.resolve(arg('--out')) : SECURE_OUT);
  const temp = out + '-tmp';
  await fs.rm(temp, { recursive: true, force: true });
  await fs.mkdir(temp, { recursive: true });
  try {
    for (const asset of ASSETS) {
      if (asset === 'data.enc.json' || asset.endsWith('.enc.json')) throw new Error('Refusing to copy campaign ciphertext');
      const dest = path.join(temp, asset);
      await fs.mkdir(path.dirname(dest), { recursive: true });
      await fs.copyFile(path.join(DOCS, asset), dest);
    }
    const html = await fs.readFile(path.join(ROOT, 'secure', 'index.html'), 'utf8');
    if (!html.includes('__BLITZ_CSP__')) throw new Error('Shell template is missing its CSP slot');
    await fs.writeFile(path.join(temp, 'index.html'), html.replace('__BLITZ_CSP__', cspFor(config)));
    await fs.copyFile(path.join(ROOT, 'secure', 'shell.css'), path.join(temp, 'shell.css'));
    await fs.writeFile(path.join(temp, 'config.js'), `globalThis.BLITZ_SECURE_CONFIG = ${JSON.stringify(config)};\n`);
    await esbuild.build({
      absWorkingDir: ROOT,
      entryPoints: [path.join(ROOT, 'secure', 'shell.js')],
      bundle: true,
      format: 'iife',
      platform: 'browser',
      target: 'es2022',
      outfile: path.join(temp, 'shell.js'),
      legalComments: 'none',
      define: { 'process.env.NODE_ENV': '"production"' },
    });
    await verifySecureShell(temp);
    await fs.rm(out, { recursive: true, force: true });
    await fs.rename(temp, out);
    console.log(config.useEmulators
      ? 'Secure shell built for the local emulator. No campaign file.'
      : 'Secure shell built from local Firebase config. No campaign file.');
    return out;
  } catch (error) {
    await fs.rm(temp, { recursive: true, force: true });
    throw error;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  buildSecureShell().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}
