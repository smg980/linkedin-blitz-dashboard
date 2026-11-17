// D0 rehearsal only. Core HTTP has no retry/redirect layer. Admin Auth's default
// HTTP client retries ECONNRESET/ETIMEDOUT/503, hiding uncertain write attempts.
import http from 'node:http';

const RESERVED = new Set(['acr', 'amr', 'at_hash', 'aud', 'auth_time', 'azp', 'cnf',
  'c_hash', 'exp', 'iat', 'iss', 'jti', 'nbf', 'nonce', 'sub', 'firebase']);

export function assertEmulatorClaims(claims) {
  if (!claims || typeof claims !== 'object' || Array.isArray(claims)
    || Object.keys(claims).some((key) => RESERVED.has(key))
    || JSON.stringify(claims).length > 1000) throw new Error('D0_CLAIMS_INVALID');
}

export function oneAttemptEmulatorClaims({ projectId, host }) {
  if (!/^demo-[a-z0-9-]+$/.test(projectId || '')
    || !/^(127\.0\.0\.1|localhost):[0-9]+$/.test(host || '')) throw new Error('D0_LOOPBACK_AUTH_REQUIRED');
  const endpoint = new URL(`http://${host}/identitytoolkit.googleapis.com/v1/projects/${projectId}/accounts:update`);
  let sealed = false;
  const closing = new Set();
  const send = (body) => {
    if (sealed) return Promise.reject(new Error('D0_TRANSPORT_SEALED'));
    const data = JSON.stringify(body);
    return new Promise((resolve, reject) => {
      const request = http.request(endpoint, { method: 'POST', agent: false,
        headers: { authorization: 'Bearer owner', 'content-type': 'application/json',
          'content-length': Buffer.byteLength(data), connection: 'close' } }, (response) => {
        let bytes = 0;
        response.on('data', (chunk) => {
          bytes += chunk.length;
          if (bytes > 1024 * 1024) response.destroy(new Error('D0_RESPONSE_TOO_LARGE'));
        });
        response.on('error', () => reject(new Error('D0_WRITE_UNCONFIRMED')));
        response.on('end', () => response.statusCode === 200 ? resolve() : reject(new Error('D0_WRITE_UNCONFIRMED')));
      });
      let closed;
      const closingPromise = new Promise((done) => { closed = done; });
      closing.add(closingPromise);
      request.once('close', () => { closing.delete(closingPromise); closed(); });
      request.once('error', () => reject(new Error('D0_WRITE_UNCONFIRMED')));
      request.end(data);
    });
  };
  return Object.freeze({
    setCustomUserClaims: (uid, claims) => {
      assertEmulatorClaims(claims);
      return send({ localId: uid, customAttributes: JSON.stringify(claims) });
    },
    revokeRefreshTokens: (uid) => send({ localId: uid, validSince: String(Math.floor(Date.now() / 1000)) }),
    async shutdown() { sealed = true; await Promise.all([...closing]); },
  });
}
