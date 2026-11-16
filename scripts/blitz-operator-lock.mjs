#!/usr/bin/env node
// Holds the per-project operator lock while a human changes owner claims (D0),
// so a Step D store run cannot overlap it. See secure/D0_OWNER_ACCESS.md.
//
//   node scripts/blitz-operator-lock.mjs hold   --project <id> [--purpose d0-claims]
//   node scripts/blitz-operator-lock.mjs status --project <id>
//
// The lock is released when this process gets Enter, end of input, SIGINT or
// SIGTERM. It never removes a lock it did not create.
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { acquireOperatorLock, lockDirectory } from '../secure/operator-lock.mjs';

function parse(argv) {
  const [command, ...rest] = argv;
  const opts = { command, purpose: 'd0-claims' };
  for (let i = 0; i < rest.length; i += 2) {
    const flag = rest[i];
    const value = rest[i + 1];
    if (!['--project', '--purpose'].includes(flag) || !value || value.startsWith('--')) throw new Error('LOCK_INVALID_ARGUMENTS');
    opts[flag.slice(2)] = value;
  }
  if (!['hold', 'status'].includes(command) || !opts.project) throw new Error('LOCK_INVALID_ARGUMENTS');
  return opts;
}

async function main(argv) {
  const opts = parse(argv);
  if (opts.command === 'status') {
    const file = path.join(lockDirectory(), `${opts.project}.lock`);
    const held = await fs.lstat(file).then(() => true, () => false);
    console.log(held ? 'OPERATOR_LOCK held' : 'OPERATOR_LOCK free');
    return;
  }
  const lock = await acquireOperatorLock({ project: opts.project, purpose: opts.purpose, dir: lockDirectory() });
  console.log('OPERATOR_LOCK held. Keep this running while claims change; press Enter to release.');
  await new Promise((resolve) => {
    const done = () => resolve();
    process.once('SIGINT', done);
    process.once('SIGTERM', done);
    process.stdin.once('data', done);
    process.stdin.once('end', done);
    process.stdin.resume();
  });
  await lock.release();
  console.log('OPERATOR_LOCK released');
  process.exit(0);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch((error) => {
    console.error(`OPERATOR_LOCK_REFUSED ${error.code || error.message}`);
    process.exit(1);
  });
}
