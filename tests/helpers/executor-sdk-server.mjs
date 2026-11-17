// Test-only loopback Auth/Firestore endpoints. No credentials or Google calls.
import http from 'node:http';
import fs from 'node:fs/promises';
import path from 'node:path';
import readline from 'node:readline';
import { startFirestoreServer, syntheticOwnerRecord } from './google-transport.mjs';
import { encryptEnvelope } from '../../secure/envelope.mjs';
import { syntheticPayload } from '../../secure/synthetic-contacts.mjs';
import { envelopeDigest } from '../../secure/campaign-store.mjs';

const [directory, ownerUid, ownerGid] = process.argv.slice(2);
const emit = (value) => process.stdout.write(JSON.stringify(value) + '\n');
const uid = 'syntheticOwnerUid01';
const envelope = await encryptEnvelope(syntheticPayload(), 'synthetic-executor-only');
const input = path.join(directory, 'envelope.json');
await fs.writeFile(input, JSON.stringify(envelope), { mode: 0o600 });
await fs.chown(input, Number(ownerUid), Number(ownerGid));
let claims = { blitzOwner: true };
let authWrites = 0;
let validSince = syntheticOwnerRecord(uid).validSince;
const auth = http.createServer(async (request, response) => {
  let text = '';
  for await (const chunk of request) text += chunk;
  const body = JSON.parse(text);
  const user = { ...syntheticOwnerRecord(uid), customAttributes: JSON.stringify(claims), validSince,
    disabled: mode === 'eligibility-changed' && firestore.state.commits.length > 0 };
  if (request.url.endsWith('accounts:update')) {
    authWrites++;
    if (body.customAttributes) claims = JSON.parse(body.customAttributes);
    if (body.validSince) { validSince = body.validSince; user.validSince = validSince; }
    response.setHeader('content-type', 'application/json');
    response.end(JSON.stringify(user));
  } else {
    response.setHeader('content-type', 'application/json');
    response.end(JSON.stringify({ users: [user] }));
  }
});
await new Promise((resolve) => auth.listen(0, '127.0.0.1', resolve));
let mode = 'known';
let release;
let firestore;
firestore = await startFirestoreServer({ tls: null, expectedToken: 'owner',
  commitFault: async (_attempt, _request, apply) => {
    emit({ event: 'commit-started' });
    if (mode === 'delay') await new Promise((resolve) => { release = resolve; });
    apply();
    emit({ event: 'applied' });
    return mode === 'unknown' ? { code: firestore.grpcStatus.UNAVAILABLE, details: 'synthetic lost ack' } : null;
  } });
emit({ event: 'ready', input, uid, digest: envelopeDigest(envelope),
  auth: `127.0.0.1:${auth.address().port}`, firestore: `127.0.0.1:${firestore.port}` });
for await (const line of readline.createInterface({ input: process.stdin })) {
  const command = JSON.parse(line);
  if (command.mode) { mode = command.mode; emit({ event: 'mode-set' }); }
  if (command.release) release?.();
  if (command.status) emit({ event: 'status', commits: firestore.state.commits.length, authWrites });
  if (command.close) {
    await firestore.close();
    await new Promise((resolve) => auth.close(resolve));
    break;
  }
}
