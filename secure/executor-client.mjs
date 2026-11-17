// Ordinary client: submits a fixed action; no settlement, release or reset API.
import fs from 'node:fs/promises';
import path from 'node:path';
import net from 'node:net';
import { isCredentialEnvKey } from './campaign-store.mjs';

export async function requestExecutor(operation, args, env) {
  const endpoint = env.BLITZ_EXECUTOR_SOCKET || '/run/master-blitz/executor.sock';
  const fail = (sent) => Object.assign(new Error('EXECUTOR_UNAVAILABLE'), {
    code: 'EXECUTOR_UNAVAILABLE', ...(sent ? { outcome: 'unknown', cleanupComplete: false } : {}),
  });
  if (!path.isAbsolute(endpoint)) throw fail(false);
  for (let current = endpoint; ; current = path.dirname(current)) {
    const info = await fs.lstat(current).catch(() => null);
    if (!info || info.isSymbolicLink() || info.uid !== 0
      || (current !== endpoint && (info.mode & 0o022))
      || (current === endpoint && !info.isSocket())) throw fail(false);
    if (path.dirname(current) === current) break;
  }
  // Client paths must be resolved before execution in the immutable service cwd.
  const canonical = [...args];
  for (let i = 0; i < canonical.length - 1; i++) {
    if (['--input', '--backup', '--receipt'].includes(canonical[i])) canonical[++i] = path.resolve(canonical[i]);
  }
  const forwarded = Object.fromEntries(Object.entries(env).filter(([key]) =>
    /^(BLITZ_STORE_(UID|CONFIRM_UID|APPROVAL)|BLITZ_D0_(PROJECT|SYNTHETIC_UID|CONFIRM_UID|APPROVAL)|FIRESTORE_EMULATOR_HOST|FIREBASE_AUTH_EMULATOR_HOST|CI|GITHUB_ACTIONS)$/.test(key)
      || isCredentialEnvKey(key) || /PASSPHRASE/i.test(key)));
  for (const key of Object.keys(forwarded)) {
    // Preserve refusal by presence without transferring token/passphrase values.
    if (isCredentialEnvKey(key)) forwarded[key] = '';
    if (/PASSPHRASE/i.test(key)) forwarded[key] = forwarded[key] ? 'present' : '';
  }
  const frame = JSON.stringify({ version: 1, operation, args: canonical, env: forwarded }) + '\n';
  if (Buffer.byteLength(frame) > 4 * 1024 * 1024) throw fail(false);
  return new Promise((resolve, reject) => {
    let sent = false;
    let finished = false;
    let data = '';
    const socket = net.createConnection(endpoint);
    socket.setEncoding('utf8');
    const stop = (error, result) => {
      if (finished) return;
      finished = true;
      socket.destroy();
      if (error) reject(error); else resolve(result);
    };
    socket.on('connect', () => { sent = true; socket.write(frame); });
    socket.on('data', (chunk) => {
      data += chunk;
      if (Buffer.byteLength(data) > 4 * 1024 * 1024) return stop(fail(sent));
      if (!data.includes('\n')) return;
      try {
        const value = JSON.parse(data.slice(0, data.indexOf('\n')));
        if (!value || !['CLEAN', 'ACTIVE', 'ACTIVE_OR_UNCONFIRMED'].includes(value.quarantine)
          || Boolean(value.result) === Boolean(value.error)) return stop(fail(sent));
        if (value.error && (!/^[A-Z][A-Z0-9_]{1,63}$/.test(value.error.code || '')
          || value.error.outcome && !['unknown', 'refused-before-write', 'committed-verified',
            'committed-eligibility-changed'].includes(value.error.outcome))) return stop(fail(sent));
        stop(null, value);
      } catch { stop(fail(sent)); }
    });
    socket.on('error', () => stop(fail(sent)));
    socket.on('close', () => { if (!finished) stop(fail(sent)); });
  });
}
