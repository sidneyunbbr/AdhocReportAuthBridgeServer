import {
  createCipheriv,
  createHmac,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  randomBytes,
  randomUUID
} from 'node:crypto';

const BASE_URL = process.env.AUTHBRIDGE_URL || 'http://127.0.0.1:3000';
const API_KEY = process.env.AUTHBRIDGE_API_KEY || 'test-api-key-secret-001';
const CLIENT_ID = process.env.AUTHBRIDGE_CLIENT_ID || 'test-client-001';

function deriveAesKey(sharedSecret, requestId) {
  return Buffer.from(hkdfSync('sha256', sharedSecret, Buffer.from(requestId), Buffer.from('authbridge-aes-key'), 32));
}

function encryptJson(payload, aesKey) {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', aesKey, iv);
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(payload), 'utf8'), cipher.final()]);
  return {
    encryptedPayload: ciphertext.toString('base64'),
    iv: iv.toString('hex'),
    authTag: cipher.getAuthTag().toString('base64')
  };
}

function hmac(secret, value) {
  return createHmac('sha256', Buffer.from(secret, 'utf8')).update(value, 'utf8').digest('base64');
}

async function fetchKeyInfo() {
  const response = await fetch(`${BASE_URL}/api/external-auth/keys`);
  return response.json();
}

async function buildEnvelope(keyInfo, overrides = {}) {
  const requestId = overrides.requestId || randomUUID();
  const timestamp = overrides.timestamp || Date.now();
  const clientKeys = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const clientPublicKey = Buffer.from(
    clientKeys.publicKey.export({ format: 'der', type: 'spki' })
  ).toString('base64');
  const sharedSecret = diffieHellman({
    privateKey: clientKeys.privateKey,
    publicKey: createPublicKey(keyInfo.publicKey)
  });
  const aesKey = deriveAesKey(sharedSecret, requestId);
  const encrypted = encryptJson({ username: 'user1', password: 'password1' }, aesKey);
  const canonical = [
    keyInfo.keyId,
    CLIENT_ID,
    requestId,
    timestamp,
    clientPublicKey,
    encrypted.encryptedPayload
  ].join('|');

  return {
    keyId: keyInfo.keyId,
    clientId: CLIENT_ID,
    requestId,
    timestamp,
    clientPublicKey,
    signature: overrides.signature || hmac(API_KEY, canonical),
    encryptedPayload: encrypted.encryptedPayload,
    iv: encrypted.iv,
    authTag: encrypted.authTag
  };
}

async function sendEnvelope(envelope) {
  const response = await fetch(`${BASE_URL}/api/external-auth/validate-secure`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-api-key': API_KEY
    },
    body: JSON.stringify(envelope)
  });
  return {
    status: response.status,
    body: await response.json()
  };
}

async function run() {
  const keyInfo = await fetchKeyInfo();

  const replayEnvelope = await buildEnvelope(keyInfo);
  console.log('Replay first request:', await sendEnvelope(replayEnvelope));
  console.log('Replay second request:', await sendEnvelope(replayEnvelope));

  const expiredEnvelope = await buildEnvelope(keyInfo, {
    timestamp: Date.now() - 10 * 60 * 1000
  });
  console.log('Expired timestamp:', await sendEnvelope(expiredEnvelope));

  const badSignatureEnvelope = await buildEnvelope(keyInfo, {
    signature: Buffer.from('invalid-signature').toString('base64')
  });
  console.log('Invalid signature:', await sendEnvelope(badSignatureEnvelope));
}

run().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
