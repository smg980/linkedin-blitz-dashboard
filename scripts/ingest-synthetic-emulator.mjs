#!/usr/bin/env node
// Encrypt the four fictional demo contacts and write the envelope to the
// Firestore emulator only. Real campaign ingestion is a separate approved step
// and this tool has no source-file argument.
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { assertEmulatorTarget } from '../secure/emulator-guard.mjs';
import { encryptEnvelope } from '../secure/envelope.mjs';
import { syntheticPayload } from '../secure/synthetic-contacts.mjs';

function arg(name) {
  const index = process.argv.indexOf(name);
  return index === -1 ? '' : (process.argv[index + 1] || '');
}

export async function ingestSyntheticEmulator({ host, projectId, uid, passphrase }) {
  if (process.env.DASHBOARD_PASSPHRASE) throw new Error('Refusing to ingest while DASHBOARD_PASSPHRASE is set');
  if (!/^[A-Za-z0-9]{4,128}$/.test(uid || '')) throw new Error('Refusing to ingest without a synthetic uid');
  if (typeof passphrase !== 'string' || passphrase.length < 12) throw new Error('BLITZ_SYNTHETIC_PASSPHRASE must be at least 12 characters');
  const target = assertEmulatorTarget({ host, projectId });
  const envelope = await encryptEnvelope(syntheticPayload(), passphrase);
  const { writeSyntheticEnvelope } = await import('../secure/emulator-write.mjs');
  await writeSyntheticEnvelope({ projectId: target.projectId, uid, envelope });
  return target;
}

async function main() {
  await ingestSyntheticEmulator({
    host: process.env.FIRESTORE_EMULATOR_HOST,
    projectId: arg('--project'),
    uid: arg('--uid'),
    passphrase: process.env.BLITZ_SYNTHETIC_PASSPHRASE || '',
  });
  console.log('Wrote fictional envelope to the local emulator. No real contacts were read.');
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().then(() => process.exit(0)).catch((error) => {
    console.error(error.message);
    process.exit(1);
  });
}
