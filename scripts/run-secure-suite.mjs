#!/usr/bin/env node
// Local Auth + Firestore emulator proof for the private shell.
// Uses a demo- project id and loopback ports only. Does not deploy.
import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs/promises';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PROJECT = 'demo-blitz-secure';
const TEST_RULES = `rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /{document=**} {
      allow read, write: if false;
    }
    match /linkedinBlitzPrivate/{uid} {
      allow get: if request.auth != null && request.auth.uid == uid;
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

const java = spawnSync('java', ['-version'], { encoding: 'utf8' });
if (java.status !== 0 && java.error) {
  console.error('Java is required to run the Firestore emulator.');
  process.exit(1);
}

const tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'blitz-secure-emulator-'));
const rulesPath = path.join(tmp, 'test.rules');
const configPath = path.join(tmp, 'firebase.json');
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

const env = { ...process.env };
delete env.DASHBOARD_PASSPHRASE;
delete env.GOOGLE_APPLICATION_CREDENTIALS;
delete env.FIREBASE_TOKEN;
const bin = path.join(ROOT, 'node_modules', '.bin', 'firebase');
const testFile = path.join(ROOT, 'tests', 'secure-live.integration.mjs');
const child = spawn(bin, [
  '--non-interactive',
  '--project', PROJECT,
  'emulators:exec',
  '--only', 'auth,firestore',
  '--project', PROJECT,
  '--config', configPath,
  `${process.execPath} --test --test-reporter spec ${testFile}`,
], { cwd: tmp, env, stdio: 'inherit' });

const code = await new Promise((resolve) => child.once('exit', (status) => resolve(status ?? 1)));
await fs.rm(tmp, { recursive: true, force: true });
process.exit(code);
