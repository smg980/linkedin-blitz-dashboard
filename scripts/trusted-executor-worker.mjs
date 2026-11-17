// Invoked only by the immutable supervisor, over its private stdin/stdout.
// Ordinary callers cannot select this program or supply settlement frames.
import readline from 'node:readline';
import fs from 'node:fs/promises';
import { isCredentialEnvKey } from '../secure/campaign-store.mjs';

if (process.platform !== 'linux' || process.getuid() === 0 || process.geteuid() !== process.getuid()
  || process.getuid() !== Number(process.env.BLITZ_EXECUTOR_UID)) throw new Error('EXECUTOR_IDENTITY_INVALID');
const capabilities = await fs.readFile('/proc/self/status', 'utf8');
for (const match of capabilities.matchAll(/^Cap(?:Inh|Prm|Eff|Amb):\s+([0-9a-f]+)$/gmi)) {
  if (BigInt(`0x${match[1]}`) !== 0n) throw new Error('EXECUTOR_PRIVILEGE_DROP_UNCONFIRMED');
}

let request;
let authorized = false;
let sdkStarted = false;
let completion;
const lines = readline.createInterface({ input: process.stdin });
const input = [];
try {
  for await (const line of lines) {
    if (Buffer.byteLength(line) > 4 * 1024 * 1024 || input.length) throw new Error('EXECUTOR_FRAME_INVALID');
    input.push(line);
  }
  if (input.length !== 1) throw new Error('EXECUTOR_FRAME_INVALID');
  request = JSON.parse(input[0]);
  const allowed = /^(BLITZ_STORE_(UID|CONFIRM_UID|APPROVAL)|BLITZ_D0_(PROJECT|SYNTHETIC_UID|CONFIRM_UID|APPROVAL)|FIRESTORE_EMULATOR_HOST|FIREBASE_AUTH_EMULATOR_HOST|CI|GITHUB_ACTIONS|DASHBOARD_PASSPHRASE)$/;
  for (const key of Object.keys(request.env)) {
    if (!allowed.test(key) && !isCredentialEnvKey(key) && !/PASSPHRASE/i.test(key)) throw new Error('EXECUTOR_ENV_INVALID');
  }
  // Preserve refusal checks for credential/CI/passphrase variables. Only the
  // two approved emulator routing variables influence the trusted process env.
  for (const key of ['FIRESTORE_EMULATOR_HOST', 'FIREBASE_AUTH_EMULATOR_HOST']) {
    if (request.env[key] !== undefined) process.env[key] = request.env[key];
  }
  const env = { ...process.env, ...request.env };
  const executorSession = Object.freeze({ started() { sdkStarted = true; }, settled() { authorized = true; } });
  if (request.operation === 'campaign') {
    const { main, parseArgs } = await import('./blitz-campaign-store.mjs');
    const opts = parseArgs(request.args);
    if (!opts.apply || opts.project !== process.env.BLITZ_EXECUTOR_PROJECT) throw new Error('EXECUTOR_PROJECT_INVALID');
    completion = { result: await main(request.args, env, { executorSession }) };
  } else if (request.operation === 'd0') {
    const { runSyntheticOwnerAction } = await import('./d0-owner-emulator.mjs');
    const args = request.args;
    if (args.some((arg) => !['--grant', '--revoke', '--apply'].includes(arg)) || new Set(args).size !== args.length
      || !args.includes('--apply') || args.filter((arg) => arg !== '--apply').length !== 1
      || env.BLITZ_D0_PROJECT !== process.env.BLITZ_EXECUTOR_PROJECT) throw new Error('EXECUTOR_PROJECT_INVALID');
    completion = { result: await runSyntheticOwnerAction({
      projectId: env.BLITZ_D0_PROJECT, uid: env.BLITZ_D0_SYNTHETIC_UID,
      confirmUid: env.BLITZ_D0_CONFIRM_UID, approval: env.BLITZ_D0_APPROVAL,
      action: args.includes('--grant') ? 'grant' : 'revoke', apply: true,
    }, { executorSession, env }) };
  } else throw new Error('EXECUTOR_OPERATION_INVALID');
} catch (error) {
  // No factory may initialize an SDK without first calling started(). Before
  // that point this fixed child can attest a validation-only refusal.
  if (!sdkStarted) { authorized = true; error.outcome = 'refused-before-write'; }
  else if (!['unknown', 'refused-before-write', 'committed-verified', 'committed-eligibility-changed'].includes(error.outcome)) error.outcome = 'unknown';
  completion = { error: { code: /^[A-Z][A-Z0-9_]{1,63}$/.test(error?.code || '') ? error.code : 'EXECUTOR_OPERATION_FAILED',
    ...(error?.outcome ? { outcome: error.outcome } : {}),
    ...(error?.cleanupComplete === false ? { cleanupComplete: false, cleanupFailures: error.cleanupFailures } : {}) } };
}
// The frame is not a client claim: only this fixed trusted child can write it.
// The supervisor also requires EOF + exit 0 before acting on the frame.
const known = ['committed-verified', 'committed-eligibility-changed', 'refused-before-write'];
const value = completion.error ?? completion.result;
const settled = authorized && known.includes(value?.outcome) && value?.cleanupComplete !== false;
await new Promise((resolve, reject) => process.stdout.write(
  JSON.stringify({ session: request?.session ?? null, settled, completion }) + '\n',
  (error) => error ? reject(error) : resolve(),
));
