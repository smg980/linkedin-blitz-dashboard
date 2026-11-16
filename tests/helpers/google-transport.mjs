// An isolated, local stand-in for the Google endpoints Step D production mode
// talks to, so the real pinned SDK clients can be exercised end to end with
// synthetic credentials and nothing leaving the machine:
//   - OAuth token refresh: an in-memory google-auth-library transporter;
//   - Firestore: a local TLS gRPC server implementing BatchGetDocuments,
//     Commit and Rollback from the pinned firestore.proto;
//   - Identity Toolkit (Admin Auth getUser): a local TLS HTTPS server reached
//     through an https.Agent that never dials any other host.
// TLS material is generated per run with openssl (macOS LibreSSL or Linux
// OpenSSL) into a temporary directory and trusted only by this process.
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import https from 'node:https';
import { createRequire } from 'node:module';
import os from 'node:os';
import path from 'node:path';
import tls from 'node:tls';

export const SYNTHETIC_ACCESS_TOKEN = 'synthetic-access-token-1';
export const SYNTHETIC_ADC = Object.freeze({
  type: 'authorized_user',
  client_id: 'synthetic-client.apps.googleusercontent.com',
  client_secret: 'synthetic-client-secret',
  refresh_token: 'synthetic-refresh-token',
  quota_project_id: 'master-intelligence-5496f',
});

// Call before any gRPC channel or https request exists in this process.
export function isolateProcessNetwork() {
  for (const key of ['grpc_proxy', 'https_proxy', 'http_proxy', 'HTTPS_PROXY', 'HTTP_PROXY', 'GRPC_PROXY',
    'FIRESTORE_EMULATOR_HOST', 'FIREBASE_AUTH_EMULATOR_HOST', 'FIRESTORE_PREFER_REST', 'GOOGLE_APPLICATION_CREDENTIALS']) {
    delete process.env[key];
  }
}

export function opensslAvailable() {
  return spawnSync('openssl', ['version'], { encoding: 'utf8' }).status === 0;
}

export async function makeLocalTls() {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'blitz-tls-'));
  const key = path.join(dir, 'key.pem');
  const cert = path.join(dir, 'cert.pem');
  const config = path.join(dir, 'openssl.cnf');
  await fsp.writeFile(config, [
    '[req]', 'distinguished_name=dn', 'x509_extensions=ext', 'prompt=no',
    '[dn]', 'CN=localhost',
    '[ext]', 'subjectAltName=DNS:localhost,IP:127.0.0.1', 'basicConstraints=critical,CA:TRUE',
    'keyUsage=critical,digitalSignature,keyCertSign', 'extendedKeyUsage=serverAuth', '',
  ].join('\n'));
  const result = spawnSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-days', '1',
    '-keyout', key, '-out', cert, '-config', config], { encoding: 'utf8' });
  if (result.status !== 0) throw new Error(`openssl failed: ${result.stderr}`);
  return { dir, key: fs.readFileSync(key), cert: fs.readFileSync(cert), certPath: cert };
}

export function tokenTransporter() {
  const calls = [];
  return {
    calls,
    async request(options) {
      calls.push({ url: options.url, method: options.method });
      return {
        status: 200,
        headers: {},
        config: options,
        data: { access_token: SYNTHETIC_ACCESS_TOKEN, expires_in: 3600, token_type: 'Bearer' },
      };
    },
  };
}

// Same gRPC and proto-loader copies as the pinned Firestore client.
function grpcModules() {
  const adminRequire = createRequire(createRequire(import.meta.url).resolve('firebase-admin/firestore'));
  const firestoreEntry = adminRequire.resolve('@google-cloud/firestore');
  const firestoreRequire = createRequire(firestoreEntry);
  const gaxRequire = createRequire(firestoreRequire.resolve('google-gax'));
  const grpc = gaxRequire('@grpc/grpc-js');
  const loader = gaxRequire('@grpc/proto-loader');
  const protos = [path.join(path.dirname(firestoreEntry), '..', 'protos'),
    path.join(path.dirname(firestoreRequire.resolve('google-gax')), '..', 'protos')];
  return { grpc, loader, protos };
}

export function encodeFields(object) {
  const value = (v) => (typeof v === 'string' ? { stringValue: v }
    : Number.isInteger(v) ? { integerValue: String(v) }
      : typeof v === 'number' ? { doubleValue: v }
        : typeof v === 'boolean' ? { booleanValue: v }
          : (() => { throw new Error('unsupported synthetic value'); })());
  return Object.fromEntries(Object.entries(object).map(([k, v]) => [k, value(v)]));
}

const ts = () => ({ seconds: String(Math.floor(Date.now() / 1000)), nanos: 0 });

// commitFault(n, request, apply) lets a test decide what Commit attempt n does:
// return null to succeed, or a gRPC status object to fail (after or before apply()).
export async function startFirestoreServer({ tls: tlsMaterial, initialFields = null, commitFault = null, onBatchGet = null }) {
  const { grpc, loader, protos } = grpcModules();
  const definition = loader.loadSync('google/firestore/v1/firestore.proto', {
    includeDirs: protos, keepCase: false, longs: String, enums: String, defaults: true, oneofs: true,
  });
  const service = grpc.loadPackageDefinition(definition).google.firestore.v1.Firestore.service;
  const state = { fields: initialFields ? structuredClone(initialFields) : null, commits: [], batchGets: 0, authorizations: [], rollbacks: 0 };
  const authorized = (call) => {
    const header = call.metadata.get('authorization')[0];
    state.authorizations.push(header);
    return header === `Bearer ${SYNTHETIC_ACCESS_TOKEN}`;
  };
  const deny = { code: grpc.status.UNAUTHENTICATED, details: 'synthetic transport: unexpected credential' };
  const server = new grpc.Server();
  server.addService(service, {
    async batchGetDocuments(call) {
      state.batchGets += 1;
      if (!authorized(call)) { call.emit('error', deny); return; }
      if (onBatchGet) await onBatchGet(state.batchGets);
      const [name] = call.request.documents;
      const message = { readTime: ts() };
      if (call.request.newTransaction) message.transaction = Buffer.from(`synthetic-tx-${state.batchGets}`);
      if (state.fields) message.found = { name, fields: state.fields, createTime: ts(), updateTime: ts() };
      else message.missing = name;
      call.write(message);
      call.end();
    },
    commit(call, callback) {
      if (!authorized(call)) { callback(deny); return; }
      const attempt = state.commits.length + 1;
      state.commits.push(structuredClone({ writes: call.request.writes.map((w) => w.operation), transaction: String(call.request.transaction) }));
      const apply = () => {
        for (const write of call.request.writes) {
          if (write.delete) state.fields = null;
          else if (write.update) state.fields = write.update.fields;
        }
      };
      const fault = commitFault ? commitFault(attempt, call.request, apply) : (apply(), null);
      if (fault) { callback(fault); return; }
      callback(null, { writeResults: call.request.writes.map(() => ({ updateTime: ts() })), commitTime: ts() });
    },
    rollback(call, callback) {
      state.rollbacks += 1;
      callback(null, {});
    },
  });
  const port = await new Promise((resolve, reject) => {
    server.bindAsync('127.0.0.1:0', grpc.ServerCredentials.createSsl(null, [{ private_key: tlsMaterial.key, cert_chain: tlsMaterial.cert }]),
      (error, bound) => (error ? reject(error) : resolve(bound)));
  });
  return { state, port, grpcStatus: grpc.status, close: () => new Promise((resolve) => server.tryShutdown(() => resolve())) };
}

// Admin Auth getUser -> POST .../accounts:lookup.
export async function startIdentityToolkit({ tls: tlsMaterial, user }) {
  const seen = [];
  const server = https.createServer({ key: tlsMaterial.key, cert: tlsMaterial.cert }, (req, res) => {
    let body = '';
    req.on('data', (chunk) => { body += chunk; });
    req.on('end', () => {
      seen.push({ host: req.headers.host, url: req.url, authorization: req.headers.authorization });
      if (req.headers.authorization !== `Bearer ${SYNTHETIC_ACCESS_TOKEN}`) {
        res.writeHead(401, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: { code: 401, message: 'UNAUTHENTICATED' } }));
        return;
      }
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ users: [user] }));
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  const agent = new (class LocalOnlyAgent extends https.Agent {
    createConnection(options, callback) {
      return tls.connect({ host: '127.0.0.1', port, servername: 'localhost', ca: tlsMaterial.cert }, callback);
    }
  })({ keepAlive: false });
  return { seen, agent, close: () => new Promise((resolve) => server.close(() => resolve())) };
}

// A synthetic owner record in Identity Toolkit's wire shape.
export function syntheticOwnerRecord(uid) {
  return {
    localId: uid,
    email: 'owner-synthetic@example.com',
    emailVerified: true,
    disabled: false,
    providerUserInfo: [{ providerId: 'google.com', rawId: 'synthetic-google-id', email: 'owner-synthetic@example.com' }],
    customAttributes: JSON.stringify({ blitzOwner: true }),
    validSince: '1794700800',
    createdAt: '1794700800000',
  };
}
