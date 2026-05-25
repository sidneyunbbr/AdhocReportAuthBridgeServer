import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { resetTestDatabase, startTestServer } from './helpers.js';

let testServer;

before(async () => {
  resetTestDatabase();
  testServer = await startTestServer(3001);
});

beforeEach(() => {
  resetTestDatabase();
});

after(async () => {
  await testServer.stop();
});

test('GET /api/external-auth/keys returns active key metadata', async () => {
  const response = await fetch(`${testServer.baseUrl}/api/external-auth/keys`);
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.keyId, 'server-key-001');
  assert.equal(body.algorithm, 'EC-P256');
  assert.match(body.publicKey, /BEGIN PUBLIC KEY/);
});
