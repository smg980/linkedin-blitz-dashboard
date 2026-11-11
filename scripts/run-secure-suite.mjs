#!/usr/bin/env node
// Local Auth + Firestore emulator proof for the private shell.
// Uses a demo- project id and loopback ports only. Does not deploy.
// A failed, killed, or timed-out integration exits nonzero even when
// emulators:exec itself reports success.
import { spawn, spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import fs from 'node:fs/promises';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { findChrome } from './secure-browser-check.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PROJECT = 'demo-blitz-secure';
const SUITE_TIMEOUT_MS = 9 * 60 * 1000;
const TEST_TIMEOUT_MS = 180000;
// Emulator-only predicate for synthetic users. Not a deployable ruleset.
const TEST_RULES = `rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /{document=**} {
      allow get, list, create, update, delete: if false;
    }
    match /blitzOwners/{uid}/campaign/current {
      allow get: if request.auth != null
        && request.auth.token.firebase.sign_in_provider == 'google.com'
        && request.auth.token.email_verified == true
        && request.auth.uid == uid
        && request.auth.token.blitzOwner == true;
      allow list, create, update, delete: if false;
    }
  }
}
`;

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

function killTree(pid) {
  if (!pid) return;
  try { process.kill(-pid, 'SIGKILL'); } catch { /* already exited */ }
}

export function launcherSource({ testFile, statusPath }) {
  return `import { spawn } from 'node:child_process';
import fs from 'node:fs';

const testFile = ${JSON.stringify(testFile)};
const statusPath = ${JSON.stringify(statusPath)};
const signals = { SIGHUP: 1, SIGINT: 2, SIGQUIT: 3, SIGKILL: 9, SIGPIPE: 13, SIGTERM: 15 };
const env = { ...process.env };
delete env.NODE_TEST_CONTEXT;
const child = spawn(process.execPath, [
  '--test',
  '--test-reporter=spec',
  '--test-force-exit',
  '--test-timeout=${TEST_TIMEOUT_MS}',
  testFile,
], { stdio: 'inherit', env });

let done = false;
function finish(status) {
  if (done) return;
  done = true;
  const code = status === 0 ? 0 : Math.min(Math.max(Number(status) || 1, 1), 255);
  try { fs.writeFileSync(statusPath, String(code) + '\\n'); } catch { /* parent treats a missing file as failure */ }
  process.exit(code);
}

child.once('exit', (code, signal) => {
  if (signal) finish(128 + (signals[signal] || 1));
  else finish(code === 0 ? 0 : (code ?? 1));
});
child.once('error', () => finish(1));
`;
}

export function reportedFailCount(output) {
  let count = null;
  for (const line of String(output || '').split(/\r?\n/)) {
    if (line.length > 80) continue;
    const match = line.match(/(?:^|\s)(?:ℹ|#)?\s*fail\s+(\d+)\s*$/);
    if (match) count = Number(match[1]);
  }
  return count;
}

// firebase emulators:exec can return 0 after the integration process is killed
// (a null wait status becomes 0). The recorded child status and the test report
// decide the suite result.
export function integrationFailure({ execCode, execSignal, output, childStatus }) {
  const text = String(output || '');
  const reasons = [];
  if (execSignal) reasons.push(`emulator command was killed by ${execSignal}`);
  if (execCode == null) reasons.push('emulator command ended without an exit code');
  else if (execCode !== 0) reasons.push(`emulator command exited ${execCode}`);
  const reported = reportedFailCount(text);
  if (reported != null && reported > 0) reasons.push(`integration reported fail ${reported}`);
  if (/^\s*✖\s+\S/m.test(text)) reasons.push('integration reported a failed test');
  if (childStatus == null || !/^\d+$/.test(String(childStatus))) {
    reasons.push('integration child did not record an exit status');
  } else if (Number(childStatus) !== 0) {
    reasons.push(`integration child exited ${childStatus}`);
  }
  if (/Script exited unsuccessfully|Script exited with signal/i.test(text)) {
    reasons.push('emulators:exec reported a script failure');
  }
  return reasons.length ? reasons.join('; ') : null;
}

export function watchChild(child, { statusPath, timeoutMs }) {
  return new Promise((resolve) => {
    let output = '';
    let settled = false;
    let abortTimer;
    const finish = (execCode, execSignal) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      clearTimeout(abortTimer);
      if (execSignal || execCode !== 0) killTree(child.pid);
      if (output.length > 1_000_000) output = output.slice(-1_000_000);
      let childStatus = null;
      try {
        const raw = readFileSync(statusPath, 'utf8').trim();
        if (/^\d+$/.test(raw)) childStatus = Number(raw);
      } catch { /* missing status is a failure */ }
      resolve({ execCode, execSignal, output, childStatus });
    };
    const append = (buf, stream) => {
      const text = buf.toString('utf8');
      output += text;
      stream.write(buf);
    };
    child.stdout?.on('data', (buf) => append(buf, process.stdout));
    child.stderr?.on('data', (buf) => append(buf, process.stderr));
    const timer = setTimeout(() => {
      killTree(child.pid);
      abortTimer = setTimeout(() => finish(null, 'SIGKILL'), 2000);
    }, timeoutMs);
    child.once('exit', (code, signal) => finish(code, signal));
    child.once('error', () => finish(1, null));
  });
}

export async function runSignalKilledIntegration() {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'blitz-secure-kill-'));
  const testFile = path.join(dir, 'hang.test.mjs');
  const statusPath = path.join(dir, 'status');
  const launcherPath = path.join(dir, 'launch.mjs');
  let child;
  try {
    await fs.writeFile(testFile, `import test from 'node:test';
import net from 'node:net';
test('hang', async () => {
  const server = net.createServer();
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  await new Promise(() => {});
});
`);
    await fs.writeFile(launcherPath, launcherSource({ testFile, statusPath }));
    const env = { ...process.env };
    delete env.NODE_TEST_CONTEXT;
    child = spawn(process.execPath, [launcherPath], {
      detached: true,
      stdio: ['ignore', 'pipe', 'pipe'],
      env,
    });
    const watchedPromise = watchChild(child, { statusPath, timeoutMs: 15000 });
    const deadline = Date.now() + 5000;
    while (Date.now() < deadline) {
      const ps = spawnSync('ps', ['-ww', '-eo', 'pid,args'], { encoding: 'utf8' });
      const line = String(ps.stdout || '').split('\n').find((row) => row.includes('--test') && row.includes(testFile));
      if (line) {
        const pid = Number(line.trim().split(/\s+/)[0]);
        if (pid && pid !== child.pid) {
          try { process.kill(pid, 'SIGKILL'); } catch { /* already exited */ }
          break;
        }
      }
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    return await watchedPromise;
  } finally {
    if (child && child.exitCode == null && child.signalCode == null) killTree(child.pid);
    await fs.rm(dir, { recursive: true, force: true });
  }
}

export async function runRecordedIntegration(testFile, { timeoutMs = 20000 } = {}) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'blitz-secure-child-'));
  const statusPath = path.join(dir, 'status');
  const launcherPath = path.join(dir, 'launch.mjs');
  try {
    await fs.writeFile(launcherPath, launcherSource({ testFile, statusPath }));
    const child = spawn(process.execPath, [launcherPath], {
      detached: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    return await watchChild(child, { statusPath, timeoutMs });
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
}

async function main() {
  try {
    await findChrome();
  } catch (error) {
    console.error(error.message || error);
    process.exit(1);
  }
  const java = spawnSync('java', ['-version'], { encoding: 'utf8' });
  if (java.status !== 0 && java.error) {
    console.error('Java is required to run the Firestore emulator.');
    process.exit(1);
  }

  const tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'blitz-secure-emulator-'));
  let failure = null;
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
      testFile: path.join(ROOT, 'tests', 'secure-live.integration.mjs'),
      statusPath,
    }));

    const env = { ...process.env };
    delete env.DASHBOARD_PASSPHRASE;
    delete env.GOOGLE_APPLICATION_CREDENTIALS;
    delete env.FIREBASE_TOKEN;
    const bin = path.join(ROOT, 'node_modules', '.bin', 'firebase');
    const command = `${shellQuote(process.execPath)} ${shellQuote(launcherPath)}`;
    const child = spawn(bin, [
      '--non-interactive',
      '--project', PROJECT,
      'emulators:exec',
      '--only', 'auth,firestore',
      '--project', PROJECT,
      '--config', configPath,
      command,
    ], { cwd: tmp, env, detached: true, stdio: ['ignore', 'pipe', 'pipe'] });
    const watched = await watchChild(child, { statusPath, timeoutMs: SUITE_TIMEOUT_MS });
    failure = integrationFailure(watched);
  } finally {
    await fs.rm(tmp, { recursive: true, force: true });
  }
  if (failure) {
    console.error(`STOP: ${failure}`);
    process.exit(1);
  }
}

const invokedDirectly = process.argv[1]
  && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url));
if (invokedDirectly) {
  try {
    await main();
  } catch (error) {
    console.error(error?.message || error);
    process.exit(1);
  }
}
