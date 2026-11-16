#!/usr/bin/env node
// Local Auth + Firestore emulator proof for the private shell.
// Uses a demo- project id and loopback ports only. Does not deploy.
// A failed, killed, or timed-out integration exits nonzero even when
// emulators:exec itself reports success.
import { spawn, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { appendFileSync, readFileSync, writeFileSync } from 'node:fs';
import fs from 'node:fs/promises';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { findChrome } from './secure-browser-check.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PROJECT = 'demo-blitz-secure';
export const SUITE_TIMEOUT_MS = 9 * 60 * 1000;
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
  if (!pid || pid === process.pid || pid <= 1) return;
  try { process.kill(-pid, 'SIGKILL'); } catch { /* already exited or not a group */ }
  try { process.kill(pid, 'SIGKILL'); } catch { /* already exited */ }
}

function stripAnsi(text) {
  return String(text || '').replace(/\u001b\[[0-9;]*[A-Za-z]/g, '');
}

function waitMs(ms) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

export function processTable() {
  const ps = spawnSync('ps', ['-ww', '-eo', 'pid,ppid,pgid,stat,args'], { encoding: 'utf8' });
  const rows = [];
  for (const line of String(ps.stdout || '').split('\n')) {
    const match = line.match(/^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\S+)\s*(.*)$/);
    if (!match) continue;
    rows.push({
      pid: Number(match[1]),
      ppid: Number(match[2]),
      pgid: Number(match[3]),
      zombie: match[4].startsWith('Z'),
      args: match[5] || '',
    });
  }
  return rows;
}

export function descendantsOf(rootPid) {
  if (!rootPid || rootPid <= 1) return [];
  const byParent = new Map();
  for (const row of processTable()) {
    if (!byParent.has(row.ppid)) byParent.set(row.ppid, []);
    byParent.get(row.ppid).push(row);
  }
  const found = [];
  const stack = [rootPid];
  const seen = new Set([rootPid]);
  while (stack.length) {
    const pid = stack.pop();
    for (const child of byParent.get(pid) || []) {
      if (seen.has(child.pid) || child.pid <= 1) continue;
      seen.add(child.pid);
      found.push(child);
      stack.push(child.pid);
    }
  }
  return found;
}

export function createTracker() {
  const tracked = new Map();
  return {
    note(rootPid) {
      for (const row of descendantsOf(rootPid)) tracked.set(row.pid, row);
    },
    reap(rootPid) {
      this.note(rootPid);
      const table = processTable();
      const own = table.find((row) => row.pid === process.pid);
      const ownPgid = own ? own.pgid : 0;
      const live = new Map(table.map((row) => [row.pid, row]));
      const killList = [];
      const consider = (row) => {
        if (!row || row.zombie || row.pid <= 1 || row.pid === process.pid) return;
        const current = live.get(row.pid);
        if (!current || current.zombie) return;
        if (row.pgid && current.pgid && row.pgid !== current.pgid) return;
        killList.push(current);
      };
      for (const row of tracked.values()) consider(row);
      if (rootPid) consider(live.get(rootPid));
      for (const row of killList) {
        if (row.pgid > 1 && row.pgid !== ownPgid) {
          try { process.kill(-row.pgid, 'SIGKILL'); } catch { /* already exited or not our group */ }
        }
        try { process.kill(row.pid, 'SIGKILL'); } catch { /* already exited */ }
      }
      const wanted = killList.map((row) => row.pid);
      const deadline = Date.now() + 2000;
      let alive = wanted;
      while (Date.now() <= deadline) {
        const still = new Set(processTable().filter((row) => !row.zombie).map((row) => row.pid));
        alive = wanted.filter((pid) => still.has(pid));
        if (!alive.length) return [];
        waitMs(50);
      }
      return alive;
    },
  };
}

function commandStill(pid, marker) {
  const ps = spawnSync('ps', ['-ww', '-p', String(pid), '-o', 'stat=,args='], { encoding: 'utf8' });
  if (ps.status !== 0) return false;
  const text = String(ps.stdout || '').trim();
  if (!text || text.startsWith('Z')) return false;
  return text.includes(marker);
}

export function installShutdown(tracker, { notePath = '' } = {}) {
  let rootPid = 0;
  let exiting = false;
  const stop = (signal, code) => {
    if (exiting) return;
    exiting = true;
    let survivors = [];
    try {
      survivors = tracker.reap(rootPid);
    } catch (error) {
      console.error(`STOP: cleanup failed: ${error.message || error}`);
      survivors = ['cleanup-failed'];
    }
    if (survivors.length) console.error(`STOP: descendants still running: ${survivors.join(',')}`);
    if (notePath) {
      try { appendFileSync(notePath, `signal=${signal}\ncode=${code}\n`); } catch { /* the exit code is still nonzero */ }
    }
    console.error(`STOP: caught ${signal}`);
    process.exit(code);
  };
  process.once('SIGINT', () => stop('SIGINT', 130));
  process.once('SIGTERM', () => stop('SIGTERM', 143));
  return {
    setRoot(pid) { rootPid = pid; },
  };
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
  for (const line of stripAnsi(output).split(/\r?\n/)) {
    const match = line.match(/(?:^|\s)(?:ℹ|#)?\s*fail\s+(\d+)\s*$/);
    if (match) count = Number(match[1]);
  }
  return count;
}

// firebase emulators:exec can return 0 after the integration process is killed
// (a null wait status becomes 0). The recorded child status and the test report
// decide the suite result.
export function integrationFailure({ execCode, execSignal, output, childStatus }) {
  const text = stripAnsi(output);
  const reasons = [];
  if (execSignal) reasons.push(`emulator command was killed by ${execSignal}`);
  if (execCode == null) reasons.push('emulator command ended without an exit code');
  else if (execCode !== 0) reasons.push(`emulator command exited ${execCode}`);
  const reported = reportedFailCount(text);
  if (reported != null && reported > 0) reasons.push(`integration reported fail ${reported}`);
  if (/^\s*✖\s+\S/m.test(text)) reasons.push('integration reported a failed test');
  // A zero exit status does not prove the complete, seven-test suite ran.
  // Require the Node spec reporter's complete summary on this invocation,
  // including the one passing iPhone viewport test. Do not cap line length:
  // indentation and color codes can make a real summary line look long.
  const expected = { tests: 7, pass: 7, fail: 0, cancelled: 0, skipped: 0, todo: 0 };
  const summary = Object.create(null);
  const duplicates = new Set();
  const iphonePass = /^✔ built shell states fit an iPhone viewport(?:\s+\(|\s*$)/;
  let iphonePasses = 0;
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    const match = trimmed.match(/^(?:ℹ|#)\s*(tests|pass|fail|cancelled|skipped|todo)\s+(\d+)$/);
    if (match) {
      const key = match[1];
      if (Object.hasOwn(summary, key)) duplicates.add(key);
      summary[key] = Number(match[2]);
    }
    if (iphonePass.test(trimmed)) iphonePasses += 1;
  }
  if (duplicates.size) reasons.push(`integration summary has duplicate fields: ${[...duplicates].join(', ')}`);
  for (const [key, value] of Object.entries(expected)) {
    if (summary[key] !== value) reasons.push(`integration summary requires ${key} ${value}, got ${summary[key] ?? 'missing'}`);
  }
  if (iphonePasses !== 1) reasons.push(`integration summary requires one passing iPhone viewport test, got ${iphonePasses}`);
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

export function watchChild(child, { statusPath, timeoutMs, tracker = createTracker() }) {
  return new Promise((resolve) => {
    let output = '';
    let settled = false;
    let timedOut = false;
    let abortTimer;
    const finish = (execCode, execSignal) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      clearTimeout(abortTimer);
      clearInterval(poll);
      if (output.length > 1_000_000) output = output.slice(-1_000_000);
      let childStatus = null;
      try {
        const raw = readFileSync(statusPath, 'utf8').trim();
        if (/^\d+$/.test(raw)) childStatus = Number(raw);
      } catch { /* missing status is a failure */ }
      let survivors;
      try {
        survivors = tracker.reap(child.pid);
      } catch (error) {
        survivors = [`cleanup-failed:${error.message || error}`];
      }
      resolve({ execCode, execSignal, output, childStatus, timedOut, survivors });
    };
    const append = (buf, stream) => {
      const text = buf.toString('utf8');
      output += text;
      stream.write(buf);
    };
    child.stdout?.on('data', (buf) => append(buf, process.stdout));
    child.stderr?.on('data', (buf) => append(buf, process.stderr));
    const poll = setInterval(() => {
      try { tracker.note(child.pid); } catch { /* process table unreadable */ }
    }, 100);
    const timer = setTimeout(() => {
      if (settled) return;
      timedOut = true;
      try { tracker.reap(child.pid); } catch { /* finish records leftovers */ }
      abortTimer = setTimeout(() => finish(null, 'SIGKILL'), 2000);
    }, timeoutMs);
    child.once('exit', (code, signal) => finish(code, signal));
    child.once('error', () => finish(1, null));
  });
}

export async function prepareAttestation(env = process.env) {
  const nonce = env.BLITZ_SECURE_ATTEST_NONCE || randomBytes(16).toString('hex');
  if (!/^[0-9a-f]{32}$/.test(nonce)) throw new Error('secure suite attestation nonce is invalid');
  const attestPath = env.BLITZ_SECURE_ATTEST_PATH || path.join(os.tmpdir(), `blitz-secure-attest-${nonce}`);
  await fs.rm(attestPath, { force: true });
  await fs.rm(`${attestPath}.${process.pid}.tmp`, { force: true });
  return { nonce, attestPath };
}

export async function writeAttestation({ attestPath, nonce }) {
  if (!/^[0-9a-f]{32}$/.test(nonce)) throw new Error('secure suite attestation nonce is invalid');
  const body = [
    `nonce=${nonce}`,
    'tests=7',
    'pass=7',
    'fail=0',
    'cancelled=0',
    'skipped=0',
    'todo=0',
    'iphone=pass',
    '',
  ].join('\n');
  const tmp = `${attestPath}.${process.pid}.tmp`;
  await fs.mkdir(path.dirname(attestPath), { recursive: true });
  try {
    await fs.writeFile(tmp, body, { mode: 0o600 });
    await fs.rename(tmp, attestPath);
  } catch (error) {
    await fs.rm(tmp, { force: true });
    throw error;
  }
}

export async function finalizeSuiteResult(watched, attestation) {
  const survivors = watched.survivors || [];
  const parsed = integrationFailure(watched);
  const survivorText = survivors.length ? `descendants still running: ${survivors.join(',')}` : '';
  if (watched.timedOut || parsed || survivorText) {
    const parts = [];
    if (watched.timedOut) parts.push('secure suite timed out');
    if (parsed) parts.push(parsed);
    if (survivorText) parts.push(survivorText);
    return { failure: parts.join('; '), exitCode: watched.timedOut ? 124 : 1 };
  }
  try {
    await writeAttestation(attestation);
  } catch (error) {
    return { failure: `cannot write secure suite attestation: ${error.message || error}`, exitCode: 1 };
  }
  return { failure: null, exitCode: 0 };
}

function spawnDetachedTree({ marker, pidFile }) {
  const helperPath = path.join(path.dirname(pidFile), `hang-helper-${process.pid}.mjs`);
  writeFileSync(helperPath, [
    "import { spawn } from 'node:child_process';",
    "import fs from 'node:fs';",
    "const grand = spawn(process.execPath, [process.argv[2]], { detached: true, stdio: 'ignore' });",
    "fs.appendFileSync(process.argv[3], 'grand=' + grand.pid + '\\n');",
    'grand.unref();',
    'setInterval(() => {}, 1000);',
    '',
  ].join('\n'));
  const child = spawn(process.execPath, [helperPath, marker, pidFile], {
    detached: true,
    stdio: 'ignore',
  });
  appendFileSync(pidFile, `helper=${child.pid}\n`);
  return child;
}

function grandchildAlive(pidFile) {
  try {
    const text = readFileSync(pidFile, 'utf8');
    const match = text.match(/^grand=(\d+)$/m);
    if (!match) return false;
    return commandStill(Number(match[1]), 'cloud-firestore-emulator');
  } catch {
    return false;
  }
}

function waitForDetachedGrandchild(pidFile) {
  const deadline = Date.now() + 5000;
  while (Date.now() < deadline) {
    let text = '';
    try { text = readFileSync(pidFile, 'utf8'); } catch { text = ''; }
    const grand = Number((text.match(/^grand=(\d+)$/m) || [])[1]);
    const helper = Number((text.match(/^helper=(\d+)$/m) || [])[1]);
    if (grand && helper) {
      const row = (pid) => {
        const ps = spawnSync('ps', ['-ww', '-p', String(pid), '-o', 'ppid=,pgid=,args='], { encoding: 'utf8' });
        if (ps.status !== 0) return null;
        const match = String(ps.stdout || '').trim().match(/^(\d+)\s+(\d+)\s+([\s\S]*)$/);
        if (!match) return null;
        return { ppid: Number(match[1]), pgid: Number(match[2]), args: match[3] };
      };
      const grandRow = row(grand);
      const helperRow = row(helper);
      if (grandRow && helperRow
        && grandRow.ppid === helper
        && grandRow.pgid !== helperRow.pgid
        && grandRow.args.includes('cloud-firestore-emulator')) {
        appendFileSync(pidFile, `grandppid=${grandRow.ppid}\ngrandpgid=${grandRow.pgid}\nhelperpgid=${helperRow.pgid}\n`);
        return true;
      }
    }
    waitMs(20);
  }
  return false;
}

export async function runProcessDrill({ mode, pidFile, marker, timeoutMs = 1000 }) {
  if (!pidFile || !marker) throw new Error('process drill requires a pid file and marker');
  appendFileSync(pidFile, `runner=${process.pid}\n`);
  const tracker = createTracker();
  const shutdown = mode === 'timeout' ? null : installShutdown(tracker, { notePath: pidFile });
  const child = spawnDetachedTree({ marker, pidFile });
  if (shutdown) shutdown.setRoot(child.pid);
  if (!waitForDetachedGrandchild(pidFile)) {
    try { tracker.reap(child.pid); } catch { /* still exit nonzero */ }
    console.error('STOP: detached grandchild was not a separate process group');
    process.exit(1);
  }
  if (mode === 'timeout') {
    const watched = await watchChild(child, {
      statusPath: path.join(path.dirname(pidFile), 'missing-integration-status'),
      timeoutMs,
      tracker,
    });
    const decision = await finalizeSuiteResult(watched, {
      attestPath: path.join(path.dirname(pidFile), 'attest-must-not-be-written'),
      nonce: 'ab'.repeat(16),
    });
    if (decision.exitCode !== 124 || grandchildAlive(pidFile)) {
      console.error(`STOP: timeout cleanup failed (${decision.failure || 'no failure'})`);
      process.exit(1);
    }
    console.error(`STOP: ${decision.failure}`);
    process.exit(124);
  }
  appendFileSync(pidFile, 'ready\n');
  await new Promise(() => {});
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
  const attestation = await prepareAttestation();
  const tracker = createTracker();
  const shutdown = installShutdown(tracker);
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
  let emulatorPid = 0;
  let reaped = false;
  let decision = { failure: 'secure suite did not finish', exitCode: 1 };
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
    emulatorPid = child.pid;
    shutdown.setRoot(emulatorPid);
    const watched = await watchChild(child, { statusPath, timeoutMs: SUITE_TIMEOUT_MS, tracker });
    reaped = true;
    decision = await finalizeSuiteResult(watched, attestation);
  } finally {
    if (!reaped && emulatorPid) {
      try { tracker.reap(emulatorPid); } catch { /* keep the recorded failure */ }
    }
    await fs.rm(tmp, { recursive: true, force: true });
  }
  if (decision.failure) {
    console.error(`STOP: ${decision.failure}`);
    process.exit(decision.exitCode || 1);
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
