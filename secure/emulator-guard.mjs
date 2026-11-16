const LOOPBACK = new Set(['127.0.0.1', 'localhost', '::1']);
const REAL_PROJECT = 'master-intelligence-5496f';

export function assertEmulatorTarget({ host, projectId }) {
  if (!host || typeof host !== 'string') throw new Error('Refusing to write: FIRESTORE_EMULATOR_HOST is not set');
  const trimmed = host.trim();
  if (!trimmed || /[/\\]/.test(trimmed) || /googleapis|firebaseio|web\.app|firebaseapp|cloud\.google|googleusercontent/i.test(trimmed)) {
    throw new Error('Refusing to write: host is not a local emulator');
  }
  let hostname = trimmed;
  let port = '';
  if (trimmed.startsWith('[')) {
    const match = trimmed.match(/^\[([^\]]+)\]:(\d+)$/);
    if (!match) throw new Error('Refusing to write: emulator host is invalid');
    hostname = match[1];
    port = match[2];
  } else {
    const idx = trimmed.lastIndexOf(':');
    if (idx <= 0) throw new Error('Refusing to write: emulator port is missing');
    hostname = trimmed.slice(0, idx);
    port = trimmed.slice(idx + 1);
  }
  if (!LOOPBACK.has(hostname)) throw new Error('Refusing to write: host is not a loopback emulator');
  const portNumber = Number(port);
  if (!/^\d+$/.test(port) || portNumber < 1 || portNumber > 65535) throw new Error('Refusing to write: emulator port is invalid');
  if (typeof projectId !== 'string' || !projectId.startsWith('demo-') || projectId.includes(REAL_PROJECT)) {
    throw new Error('Refusing to write: emulator project id must use the demo- prefix');
  }
  return { host: `${hostname}:${port}`, hostname, port: portNumber, projectId };
}
