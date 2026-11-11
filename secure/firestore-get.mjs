import { isEnvelope } from './envelope.mjs';

export function privateDocumentUrl({ origin, projectId, uid }) {
  if (!/^https?:\/\/[^/]+$/.test(origin)) throw new Error('Unexpected Firestore origin');
  if (!/^[A-Za-z0-9_-]+$/.test(projectId)) throw new Error('Unexpected project id');
  if (!/^[A-Za-z0-9_-]+$/.test(uid)) throw new Error('Unexpected uid');
  return `${origin}/v1/projects/${projectId}/databases/(default)/documents/linkedinBlitzPrivate/${uid}`;
}

export function envelopeFromFirestoreFields(fields) {
  const str = (key) => {
    const value = fields?.[key];
    if (!value || typeof value.stringValue !== 'string') throw new Error('Missing field');
    return value.stringValue;
  };
  const num = (key) => {
    const value = fields?.[key];
    const raw = value?.integerValue ?? value?.doubleValue;
    if (raw == null || raw === '') throw new Error('Missing field');
    return Number(raw);
  };
  return {
    v: num('v'),
    alg: str('alg'),
    kdf: str('kdf'),
    iterations: num('iterations'),
    salt: str('salt'),
    iv: str('iv'),
    ct: str('ct'),
  };
}

export async function readPrivateDocument({ origin, projectId, uid, token }, fetchImpl = fetch) {
  const url = privateDocumentUrl({ origin, projectId, uid });
  let response;
  try {
    response = await fetchImpl(url, {
      method: 'GET',
      cache: 'no-store',
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    });
  } catch {
    return { status: 'denied' };
  }
  if (response.status === 404) return { status: 'missing' };
  if (!response.ok) return { status: 'denied' };
  try {
    const body = await response.json();
    const envelope = envelopeFromFirestoreFields(body.fields);
    if (!isEnvelope(envelope)) return { status: 'denied' };
    return { status: 'ok', envelope };
  } catch {
    return { status: 'denied' };
  }
}
