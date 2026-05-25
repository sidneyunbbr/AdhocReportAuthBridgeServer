import test, { after, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { DEFAULT_SEED } from '../../data/seed.js';
import { buildValidEnvelope, resetTestDatabase, startTestServer } from './helpers.js';

let testServer;

async function postEnvelope(envelope, apiKey = DEFAULT_SEED.apiKey) {
  const response = await fetch(`${testServer.baseUrl}/api/external-auth/validate-secure`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-api-key': apiKey
    },
    body: JSON.stringify(envelope)
  });

  return {
    response,
    body: await response.json()
  };
}

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

test('valid happy path returns encrypted success response', async () => {
  const built = buildValidEnvelope();
  const { response, body } = await postEnvelope(built.envelope);
  const decrypted = built.decryptResponse(body);

  assert.equal(response.status, 200);
  assert.equal(body.status, 'success');
  assert.equal(decrypted.authenticated, true);
  assert.equal(decrypted.username, 'user1');
  assert.equal(typeof decrypted.sessionRef, 'string');
  assert.equal(response.headers.get('x-request-ref') !== null, true);
});

test('missing required fields returns 400', async () => {
  const { response, body } = await postEnvelope({});

  assert.equal(response.status, 400);
  assert.equal(body.error, 'invalid_envelope');
});

test('expired timestamp returns 408', async () => {
  const built = buildValidEnvelope({
    timestamp: Date.now() - 10 * 60 * 1000
  });
  const { response, body } = await postEnvelope(built.envelope);

  assert.equal(response.status, 408);
  assert.equal(body.error, 'timestamp_expired');
});

test('replay attack returns 409 on second request', async () => {
  const built = buildValidEnvelope();
  const first = await postEnvelope(built.envelope);
  const second = await postEnvelope(built.envelope);

  assert.equal(first.response.status, 200);
  assert.equal(second.response.status, 409);
  assert.equal(second.body.error, 'replay_detected');
});

test('invalid signature returns 422', async () => {
  const built = buildValidEnvelope({ signature: 'invalid-signature' });
  const { response, body } = await postEnvelope(built.envelope);

  assert.equal(response.status, 422);
  assert.equal(body.error, 'signature_invalid');
});

test('decryption failure returns 422', async () => {
  const built = buildValidEnvelope({ authTag: Buffer.from('broken-tag').toString('base64') });
  const { response, body } = await postEnvelope(built.envelope);

  assert.equal(response.status, 422);
  assert.equal(body.error, 'decryption_failed');
});

test('invalid credentials returns 401', async () => {
  const built = buildValidEnvelope({
    credentials: { username: 'user1', password: 'wrong-password' }
  });
  const { response, body } = await postEnvelope(built.envelope);

  assert.equal(response.status, 401);
  assert.equal(body.error, 'authentication_failed');
});
