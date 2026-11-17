#!/usr/bin/env node
// Manual hold/status used the obsolete O_EXCL protocol. A manual claim command
// can outlive its lock holder, so this command cannot authorize a safe release
// or report executor occupancy from a pathname. Use only the trusted executor.
import path from 'node:path';
import { fileURLToPath } from 'node:url';

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
  parse(argv);
  throw new Error('LOCK_USE_TRUSTED_EXECUTOR');
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch((error) => {
    console.error(`OPERATOR_LOCK_REFUSED ${error.code || error.message}`);
    process.exit(1);
  });
}
