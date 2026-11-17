// Functional emulator tests supply a private in-process capability instead of
// requiring an installed privileged service. Full CLI/OS/IPC tests are in
// trusted-executor-supervisor.test.py; this is not a runtime argv/env bypass.
import assert from 'node:assert/strict';
import { runSyntheticOwnerAction as executeD0 } from '../../scripts/d0-owner-emulator.mjs';

export async function runSyntheticOwnerAction(options) {
  if (!options.apply) return executeD0(options);
  let started = 0;
  let settled = 0;
  const result = await executeD0(options, { executorSession: {
    started() { started++; }, settled() { settled++; },
  } });
  assert.equal(started, 1);
  assert.equal(settled, 1);
  assert.notEqual(result.cleanupComplete, false);
  assert.equal(result.outcome, 'committed-verified');
  const { outcome, ...booleans } = result;
  return booleans;
}
