import test from 'node:test';
import assert from 'node:assert/strict';
import { diffieHellman, generateKeyPairSync } from 'node:crypto';
import {
  createHmacSignature,
  decryptPayload,
  deriveAesKey,
  deriveSharedSecret,
  encryptPayload,
  generateEphemeralKeyPair,
  generateSalt,
  hashApiKey,
  hashPassword,
  signData,
  verifyHmacSignature,
  verifyPassword,
  verifySignature
} from '../crypto/index.js';

test('generateEphemeralKeyPair and deriveSharedSecret produce matching secrets', () => {
  const serverKeys = generateEphemeralKeyPair();
  const clientKeys = generateEphemeralKeyPair();
  const clientPublicKey = Buffer.from(
    clientKeys.publicKey.export({ format: 'der', type: 'spki' })
  ).toString('base64');

  const serverSecret = deriveSharedSecret(serverKeys.privateKey, clientPublicKey);
  const clientSecret = diffieHellman({
    privateKey: clientKeys.privateKey,
    publicKey: serverKeys.publicKey
  });

  assert.deepEqual(serverSecret, clientSecret);
});

test('deriveAesKey is stable for same secret and salt', () => {
  const secret = Buffer.from('shared-secret');
  const keyA = deriveAesKey(secret, 'authbridge-aes-key', 'salt-1');
  const keyB = deriveAesKey(secret, 'authbridge-aes-key', 'salt-1');

  assert.equal(keyA.length, 32);
  assert.deepEqual(keyA, keyB);
});

test('encryptPayload and decryptPayload roundtrip', () => {
  const aesKey = deriveAesKey(Buffer.from('abc'), 'authbridge-aes-key', 'salt');
  const encrypted = encryptPayload(JSON.stringify({ hello: 'world' }), aesKey);
  const decrypted = decryptPayload(encrypted.ciphertext, aesKey, encrypted.iv, encrypted.authTag);

  assert.equal(decrypted.toString('utf8'), '{"hello":"world"}');
});

test('signData and verifySignature roundtrip', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const signature = signData('message', privateKey);

  assert.equal(verifySignature('message', signature, publicKey), true);
  assert.equal(verifySignature('tampered', signature, publicKey), false);
});

test('hmac helpers verify canonical content', () => {
  const signature = createHmacSignature('secret', 'payload');

  assert.equal(verifyHmacSignature('secret', 'payload', signature), true);
  assert.equal(verifyHmacSignature('secret', 'other', signature), false);
});

test('hash helpers create expected formats', () => {
  const salt = generateSalt();
  const passwordHash = hashPassword('password1', salt);

  assert.equal(hashApiKey('test-api-key-secret-001').length, 64);
  assert.equal(passwordHash.length, 64);
  assert.equal(verifyPassword('password1', `sha256:${salt}:${passwordHash}`), true);
});
