// Same AES-256-GCM / PBKDF2-SHA256 envelope as docs/app.js and scripts/build.mjs.
// Those files stay on the GitHub Pages path. This module is the shared
// implementation for the private shell, its tests, and emulator ingestion.
const ITERATIONS = 600_000;

function webCrypto() {
  const crypto = globalThis.crypto;
  if (!crypto?.subtle || !crypto.getRandomValues) throw new Error('Web Crypto is not available');
  return crypto;
}

function bytesToB64(bytes) {
  let binary = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

function b64ToBytes(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export function isEnvelope(blob) {
  if (!blob || blob.v !== 1 || blob.alg !== 'AES-256-GCM' || blob.kdf !== 'PBKDF2-SHA256' || blob.iterations !== ITERATIONS) return false;
  if (typeof blob.salt !== 'string' || typeof blob.iv !== 'string' || typeof blob.ct !== 'string') return false;
  try {
    const salt = b64ToBytes(blob.salt);
    const iv = b64ToBytes(blob.iv);
    const ct = b64ToBytes(blob.ct);
    return salt.length === 16 && iv.length === 12 && ct.length > 16;
  } catch {
    return false;
  }
}

export async function encryptEnvelope(obj, passphrase) {
  if (typeof passphrase !== 'string' || passphrase.length < 12) throw new Error('Passphrase is too short');
  const crypto = webCrypto();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: ITERATIONS, hash: 'SHA-256' },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt'],
  );
  const ct = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    new TextEncoder().encode(JSON.stringify(obj)),
  ));
  return {
    v: 1,
    alg: 'AES-256-GCM',
    kdf: 'PBKDF2-SHA256',
    iterations: ITERATIONS,
    salt: bytesToB64(salt),
    iv: bytesToB64(iv),
    ct: bytesToB64(ct),
  };
}

export async function decryptEnvelope(blob, passphrase) {
  if (!isEnvelope(blob)) throw new Error('Unsupported or invalid encrypted data format.');
  const crypto = webCrypto();
  const salt = b64ToBytes(blob.salt);
  const iv = b64ToBytes(blob.iv);
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: blob.iterations, hash: 'SHA-256' },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt'],
  );
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, b64ToBytes(blob.ct));
  return JSON.parse(new TextDecoder().decode(pt));
}

export { ITERATIONS };
