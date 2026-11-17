import assert from 'node:assert/strict';
import http from 'node:http';
import { once } from 'node:events';
import test from 'node:test';
import { runSyntheticOwnerAction } from '../scripts/d0-owner-emulator.mjs';

for (const fault of [false, true]) {
  test(`owned D0 performs one claim write, ${fault ? 'quarantining a lost acknowledgement' : 'settling after verification'}`, async () => {
    let mutations = 0;
    let claims = {};
    const user = () => ({ localId: 'synthetic-d0-owner', email: 'synthetic@example.com', emailVerified: true,
      providerUserInfo: [{ providerId: 'google.com', rawId: 'synthetic' }],
      customAttributes: JSON.stringify(claims), validSince: '0' });
    const server = http.createServer(async (request, response) => {
      let text = '';
      for await (const chunk of request) text += chunk;
      const body = JSON.parse(text);
      if (request.url.endsWith('accounts:update')) {
        mutations++;
        claims = JSON.parse(body.customAttributes);
        if (fault) { response.destroy(); return; }
        response.setHeader('content-type', 'application/json');
        response.end(JSON.stringify(user()));
      } else {
        response.setHeader('content-type', 'application/json');
        response.end(JSON.stringify({ users: [user()] }));
      }
    });
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    const previous = process.env.FIREBASE_AUTH_EMULATOR_HOST;
    process.env.FIREBASE_AUTH_EMULATOR_HOST = `127.0.0.1:${server.address().port}`;
    let settled = 0;
    try {
      const options = { projectId: 'demo-owned-d0', uid: 'synthetic-d0-owner', action: 'grant',
        apply: true, confirmUid: 'synthetic-d0-owner', approval: 'APPLY_SYNTHETIC_ONLY' };
      const value = await runSyntheticOwnerAction(options, {
        executorSession: { started() {}, settled() { settled++; } },
        env: { FIREBASE_AUTH_EMULATOR_HOST: process.env.FIREBASE_AUTH_EMULATOR_HOST },
      }).catch((error) => error);
      assert.equal(mutations, 1);
      assert.equal(settled, fault ? 0 : 1);
      if (fault) {
        assert.equal(value.outcome, 'unknown');
        assert.equal(value.cleanupComplete, false);
      } else {
        assert.equal(value.verified, true);
        assert.equal(value.owner, true);
      }
    } finally {
      if (previous === undefined) delete process.env.FIREBASE_AUTH_EMULATOR_HOST;
      else process.env.FIREBASE_AUTH_EMULATOR_HOST = previous;
      await new Promise((resolve) => server.close(resolve));
    }
  });
}
