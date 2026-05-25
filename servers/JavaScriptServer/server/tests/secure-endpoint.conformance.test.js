/**
 * Test purpose:
 * Conformance-oriented validation for critical secure endpoint behaviors:
 * unsupported protocol, missing API key, replay detection, and successful secure response envelope.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createCipheriv,
  createDecipheriv,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  randomBytes,
  sign,
  verify
} from 'node:crypto';
import { createApp } from '../src/app.js';
import { getDemoClientSigningPrivateKey } from '../src/crypto/keyStore.js';

const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

// Test-side helpers intentionally mirror production encoding functions for deterministic envelopes.
function toBase64Url(buffer) {
  return Buffer.from(buffer)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function fromBase64Url(value) {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized.length % 4 === 0 ? normalized : normalized + '='.repeat(4 - (normalized.length % 4));
  return Buffer.from(padded, 'base64');
}

function toX25519PublicKey(rawBytes) {
  return createPublicKey({ key: Buffer.concat([X25519_SPKI_PREFIX, rawBytes]), format: 'der', type: 'spki' });
}

function toEd25519PublicKey(rawBytes) {
  return createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, rawBytes]), format: 'der', type: 'spki' });
}

function exportRawX25519PublicKey(publicKey) {
  const der = publicKey.export({ format: 'der', type: 'spki' });
  return Buffer.from(der).subarray(Buffer.from(der).length - 32);
}

// Canonical request signature string (must stay aligned with server/src/crypto/signature.js).
function buildRequestSigningInput(envelope) {
  return Buffer.from(
    [
      envelope.protocolVersion,
      envelope.keyId,
      envelope.signatureKeyId,
      envelope.clientId,
      envelope.requestId,
      envelope.timestampUtc,
      envelope.clientEphemeralPublicKey,
      envelope.nonce,
      envelope.aad,
      envelope.ciphertext,
      envelope.tag
    ].join('\n'),
    'utf8'
  );
}

// Canonical response signature string for verifying successful secure responses.
function buildResponseSigningInput(envelope) {
  return Buffer.from(
    [
      envelope.protocolVersion,
      envelope.responseId,
      envelope.requestId,
      envelope.timestampUtc,
      envelope.nonce,
      envelope.aad,
      envelope.ciphertext,
      envelope.tag,
      envelope.signatureKeyId
    ].join('\n'),
    'utf8'
  );
}

// Deterministic key derivation shared by test and server crypto module.
function deriveKey(sharedSecret, requestId) {
  return Buffer.from(
    hkdfSync(
      'sha256',
      sharedSecret,
      Buffer.from(requestId, 'utf8'),
      Buffer.from('authbridge-validate-secure:v2', 'utf8'),
      32
    )
  );
}

// Builds one valid signed+encrypted request payload for multiple conformance scenarios.
async function buildSecureRequestPayload(serverOrigin, requestIdOverride) {
  const keysResponse = await fetch(`${serverOrigin}/api/external-auth/keys`);
  const keys = await keysResponse.json();

  // Use generateKeyPairSync + diffieHellman (createECDH('x25519') is not supported here).
  const clientKeyPair = generateKeyPairSync('x25519');
  const serverPublicKey = toX25519PublicKey(fromBase64Url(keys.encryption.publicKey));
  const sharedSecret = diffieHellman({
    privateKey: clientKeyPair.privateKey,
    publicKey: serverPublicKey
  });

  const requestId = requestIdOverride || crypto.randomUUID();
  const timestampUtc = new Date().toISOString();
  const derivedKey = deriveKey(sharedSecret, requestId);

  const aadObject = {
    protocolVersion: keys.protocolVersion,
    clientId: 'customer-a-prod',
    requestId,
    timestampUtc,
    keyId: keys.encryption.keyId,
    signatureKeyId: 'client-sig-2026-05'
  };

  const plaintext = {
    username: 'external.user',
    externalUserId: null,
    password: 'external.pass',
    correlationId: `corr-${requestId}`,
    requestedScopes: ['validate-login']
  };

  const nonce = randomBytes(12);
  const aadBytes = Buffer.from(JSON.stringify(aadObject), 'utf8');
  const plaintextBytes = Buffer.from(JSON.stringify(plaintext), 'utf8');

  const cipher = createCipheriv('aes-256-gcm', derivedKey, nonce);
  cipher.setAAD(aadBytes);
  const ciphertext = Buffer.concat([cipher.update(plaintextBytes), cipher.final()]);
  const tag = cipher.getAuthTag();

  const envelope = {
    protocolVersion: keys.protocolVersion,
    keyId: keys.encryption.keyId,
    signatureKeyId: 'client-sig-2026-05',
    clientId: 'customer-a-prod',
    requestId,
    timestampUtc,
    clientEphemeralPublicKey: toBase64Url(exportRawX25519PublicKey(clientKeyPair.publicKey)),
    nonce: toBase64Url(nonce),
    aad: toBase64Url(aadBytes),
    ciphertext: toBase64Url(ciphertext),
    tag: toBase64Url(tag),
    signature: null
  };

  const signingInput = buildRequestSigningInput(envelope);
  envelope.signature = toBase64Url(sign(null, signingInput, getDemoClientSigningPrivateKey()));

  return {
    keys,
    envelope,
    derivedKey
  };
}

let server;
let serverOrigin;

test.before(async () => {
  // Isolate test runtime config from developer local defaults.
  process.env.AUTHBRIDGE_REQUEST_API_KEY = 'test-shared-key';
  process.env.AUTHBRIDGE_REQUIRE_REQUEST_API_KEY = 'true';
  process.env.AUTHBRIDGE_SECURE_PROTOCOL_VERSION = '2.0';
  process.env.AUTHBRIDGE_RESET_SHARED_DATA_ON_START = 'true';

  const app = createApp();
  server = app.listen(0);

  await new Promise((resolve) => server.once('listening', resolve));
  const address = server.address();
  serverOrigin = `http://127.0.0.1:${address.port}`;
});

test.after(async () => {
  await new Promise((resolve) => server.close(resolve));
});

test('should reject missing API key', async () => {
  const payload = await buildSecureRequestPayload(serverOrigin);

  const response = await fetch(`${serverOrigin}/api/external-auth/validate-secure`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-AuthBridge-Protocol': '2.0'
    },
    body: JSON.stringify(payload.envelope)
  });

  assert.equal(response.status, 401);
  const body = await response.json();
  assert.equal(body.errorCode, 'bridge-unauthorized-caller');
});

test('should reject unsupported protocol header', async () => {
  const payload = await buildSecureRequestPayload(serverOrigin);

  const response = await fetch(`${serverOrigin}/api/external-auth/validate-secure`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Bridge-Api-Key': 'test-shared-key',
      'X-AuthBridge-Protocol': '1.0'
    },
    body: JSON.stringify(payload.envelope)
  });

  assert.equal(response.status, 422);
  const body = await response.json();
  assert.equal(body.errorCode, 'unsupported-protocol');
});

test('should detect replay for duplicated clientId/requestId', async () => {
  // Fixed requestId allows deterministic replay check: first request accepted, second rejected.
  const payload = await buildSecureRequestPayload(serverOrigin, 'replay-fixed-id-001');

  const first = await fetch(`${serverOrigin}/api/external-auth/validate-secure`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Bridge-Api-Key': 'test-shared-key',
      'X-AuthBridge-Protocol': '2.0'
    },
    body: JSON.stringify(payload.envelope)
  });

  assert.equal(first.status, 200);

  const second = await fetch(`${serverOrigin}/api/external-auth/validate-secure`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Bridge-Api-Key': 'test-shared-key',
      'X-AuthBridge-Protocol': '2.0'
    },
    body: JSON.stringify(payload.envelope)
  });

  assert.equal(second.status, 409);
  const body = await second.json();
  assert.equal(body.errorCode, 'request-replayed');
});

test('should return signed+encrypted envelope for valid secure request', async () => {
  const payload = await buildSecureRequestPayload(serverOrigin);

  const response = await fetch(`${serverOrigin}/api/external-auth/validate-secure`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Bridge-Api-Key': 'test-shared-key',
      'X-AuthBridge-Protocol': '2.0'
    },
    body: JSON.stringify(payload.envelope)
  });

  assert.equal(response.status, 200);

  const envelope = await response.json();
  assert.equal(envelope.protocolVersion, '2.0');
  assert.ok(envelope.signature);
  assert.ok(envelope.ciphertext);

  const signatureValid = verify(
    null,
    buildResponseSigningInput(envelope),
    toEd25519PublicKey(fromBase64Url(payload.keys.signature.publicKey)),
    fromBase64Url(envelope.signature)
  );

  assert.equal(signatureValid, true);

  const decipher = createDecipheriv('aes-256-gcm', payload.derivedKey, fromBase64Url(envelope.nonce));
  decipher.setAAD(fromBase64Url(envelope.aad));
  decipher.setAuthTag(fromBase64Url(envelope.tag));

  const decrypted = Buffer.concat([
    decipher.update(fromBase64Url(envelope.ciphertext)),
    decipher.final()
  ]);

  const businessPayload = JSON.parse(decrypted.toString('utf8'));
  assert.equal(businessPayload.isValid, true);
  assert.equal(businessPayload.externalUserId, 'external-user-001');
});
