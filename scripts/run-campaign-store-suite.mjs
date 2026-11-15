#!/usr/bin/env node
// Runs tests/campaign-store.integration.mjs under local Auth and Firestore
// emulators (project demo-blitz-store) with the secure-shell emulator rules.
// Reuses the secure suite's process tracking, watchdog and signal cleanup.
// Success needs the child's recorded exit 0 and exactly one complete summary of
// EXPECTED_TESTS passing tests; an emulators:exec exit code alone is not proof.
import fs from 'node:fs/promises';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createTracker, installShutdown, launcherSource, TEST_RULES, watchChild } from './run-secure-suite.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PROJECT = 'demo-blitz-store';
export const EXPECTED_TESTS = 3;
const TIMEOUT_MS = 6 * 60 * 1000;

function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

function shellQuote(value) {
  return `'${String(value).replaceAll("'", `'\\''`)}'`;
}

export function storeSuiteFailure({ execCode, execSignal, output, childStatus, timedOut, survivors = [] }) {
  const text = String(output || '').replace(/\u001b\[[0-9;]*[A-Za-z]/g, '');
  const reasons = [];
  if (timedOut) reasons.push('suite timed out');
  if (execSignal) reasons.push(`emulator command was killed by ${execSignal}`);
  if (execCode !== 0) reasons.push(`emulator command exited ${execCode}`);
  if (childStatus !== 0) reasons.push(`integration child status ${childStatus ?? 'missing'}`);
  if (survivors.length) reasons.push(`descendants still running: ${survivors.join(',')}`);
  const expected = { tests: EXPECTED_TESTS, pass: EXPECTED_TESTS, fail: 0, cancelled: 0, skipped: 0, todo: 0 };
  const seen = Object.create(null);
  for (const line of text.split(/\r?\n/)) {
    const match = line.trim().match(/^(?:ℹ|#)\s*(tests|pass|fail|cancelled|skipped|todo)\s+(\d+)$/);
    if (!match) continue;
    if (Object.hasOwn(seen, match[1])) reasons.push(`duplicate summary field ${match[1]}`);
    seen[match[1]] = Number(match[2]);
  }
  for (const [key, value] of Object.entries(expected)) {
    if (seen[key] !== value) reasons.push(`summary requires ${key} ${value}, got ${seen[key] ?? 'missing'}`);
  }
  if (/^\s*✖\s+\S/m.test(text)) reasons.push('a test reported failure');
  return reasons.length ? reasons.join('; ') : null;
}

async function main() {
  const tracker = createTracker();
  const shutdown = installShutdown(tracker);
  const tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'blitz-store-emulator-'));
  let failure = 'campaign store suite did not finish';
  try {
    const rulesPath = path.join(tmp, 'test.rules');
    const configPath = path.join(tmp, 'firebase.json');
    const statusPath = path.join(tmp, 'integration-status');
    const launcherPath = path.join(tmp, 'launch.mjs');
    const [authPort, firestorePort, hubPort, logPort] = await Promise.all([freePort(), freePort(), freePort(), freePort()]);
    await fs.writeFile(rulesPath, TEST_RULES);
    await fs.writeFile(configPath, JSON.stringify({
      emulators: {
        auth: { host: '127.0.0.1', port: authPort },
        firestore: { host: '127.0.0.1', port: firestorePort },
        ui: { enabled: false },
        hub: { host: '127.0.0.1', port: hubPort },
        logging: { host: '127.0.0.1', port: logPort },
        singleProjectMode: true,
      },
      firestore: { rules: rulesPath },
    }, null, 2));
    await fs.writeFile(launcherPath, launcherSource({
      testFile: path.join(ROOT, 'tests', 'campaign-store.integration.mjs'),
      statusPath,
    }));
    const env = { ...process.env };
    for (const key of Object.keys(env)) {
      if (/PASSPHRASE|^GOOGLE_APPLICATION_CREDENTIALS$|^FIREBASE_TOKEN$|^BLITZ_STORE_/.test(key)) delete env[key];
    }
    const child = spawn(path.join(ROOT, 'node_modules', '.bin', 'firebase'), [
      '--non-interactive', '--project', PROJECT, 'emulators:exec', '--only', 'auth,firestore',
      '--config', configPath, `${shellQuote(process.execPath)} ${shellQuote(launcherPath)}`,
    ], { cwd: tmp, env, detached: true, stdio: ['ignore', 'pipe', 'pipe'] });
    shutdown.setRoot(child.pid);
    const watched = await watchChild(child, { statusPath, timeoutMs: TIMEOUT_MS, tracker });
    failure = storeSuiteFailure(watched);
  } finally {
    await fs.rm(tmp, { recursive: true, force: true });
  }
  if (failure) {
    console.error(`STOP: ${failure}`);
    process.exit(1);
  }
  console.log(`Campaign store emulator suite: ${EXPECTED_TESTS}/${EXPECTED_TESTS} passed.`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    console.error(`STOP: ${error?.message || error}`);
    process.exit(1);
  });
}
