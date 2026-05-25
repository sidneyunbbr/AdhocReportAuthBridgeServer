import {
  createCipheriv,
  createDecipheriv,
  createHmac,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  randomUUID,
  randomBytes
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

function decryptJson(ciphertext, aesKey, iv, authTag) {
  const decipher = createDecipheriv('aes-256-gcm', aesKey, Buffer.from(iv, 'hex'));
  decipher.setAuthTag(Buffer.from(authTag, 'base64'));
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(ciphertext, 'base64')),
    decipher.final()
  ]);
  return JSON.parse(plaintext.toString('utf8'));
}

function hmac(secret, value) {
  return createHmac('sha256', Buffer.from(secret, 'utf8')).update(value, 'utf8').digest('base64');
}

async function fetchServerKey() {
  const response = await fetch(`${BASE_URL}/api/external-auth/keys`);
  if (!response.ok) {
    throw new Error(`Key fetch failed with status ${response.status}`);
  }
  return response.json();
}

async function validateCredentials(credentials) {
  const keyInfo = await fetchServerKey();
  const requestId = randomUUID();
  const timestamp = Date.now();
  const clientKeys = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const clientPublicKey = Buffer.from(
    clientKeys.publicKey.export({ format: 'der', type: 'spki' })
  ).toString('base64');
  const sharedSecret = diffieHellman({
    privateKey: clientKeys.privateKey,
    publicKey: createPublicKey(keyInfo.publicKey)
  });
  const aesKey = deriveAesKey(sharedSecret, requestId);
  const encrypted = encryptJson(credentials, aesKey);
  const canonical = [
    keyInfo.keyId,
    CLIENT_ID,
    requestId,
    timestamp,
    clientPublicKey,
    encrypted.encryptedPayload
  ].join('|');
  const envelope = {
    keyId: keyInfo.keyId,
    clientId: CLIENT_ID,
    requestId,
    timestamp,
    clientPublicKey,
    signature: hmac(API_KEY, canonical),
    encryptedPayload: encrypted.encryptedPayload,
    iv: encrypted.iv,
    authTag: encrypted.authTag
  };

  const response = await fetch(`${BASE_URL}/api/external-auth/validate-secure`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-api-key': API_KEY
    },
    body: JSON.stringify(envelope)
  });
  const body = await response.json();

  if (!response.ok) {
    return { ok: false, status: response.status, body };
  }

  return {
    ok: true,
    status: response.status,
    body,
    decrypted: decryptJson(body.encryptedResult, aesKey, body.iv, body.authTag)
  };
}

async function run() {
  const happyPath = await validateCredentials({ username: 'user1', password: 'password1' });
  console.log('Happy path:', happyPath);

  const wrongCredentials = await validateCredentials({ username: 'user1', password: 'wrong-password' });
  console.log('Wrong credentials:', wrongCredentials);
}

run().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
