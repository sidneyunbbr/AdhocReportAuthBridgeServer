import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  randomBytes,
  sign,
  timingSafeEqual,
  verify
} from 'node:crypto';

function toBuffer(value) {
  return Buffer.isBuffer(value) ? value : Buffer.from(String(value), 'utf8');
}

function normalizePrivateKey(privateKey) {
  return typeof privateKey === 'string' ? createPrivateKey(privateKey) : privateKey;
}

function normalizePublicKey(publicKey) {
  if (typeof publicKey !== 'string') {
    return publicKey;
  }

  if (publicKey.includes('BEGIN')) {
    return createPublicKey(publicKey);
  }

  return createPublicKey({
    key: Buffer.from(publicKey, 'base64'),
    format: 'der',
    type: 'spki'
  });
}

export function generateEphemeralKeyPair() {
  return generateKeyPairSync('ec', { namedCurve: 'P-256' });
}

export function deriveSharedSecret(serverPrivateKey, clientPublicKeyPem) {
  return diffieHellman({
    privateKey: normalizePrivateKey(serverPrivateKey),
    publicKey: normalizePublicKey(clientPublicKeyPem)
  });
}

export function deriveAesKey(sharedSecret, info = 'authbridge-aes-key', salt = '') {
  return Buffer.from(
    hkdfSync('sha256', sharedSecret, toBuffer(salt), Buffer.from(info, 'utf8'), 32)
  );
}

export function encryptPayload(plaintext, aesKey) {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', aesKey, iv);
  const ciphertext = Buffer.concat([cipher.update(toBuffer(plaintext)), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return {
    iv: iv.toString('hex'),
    ciphertext: ciphertext.toString('base64'),
    authTag: authTag.toString('base64')
  };
}

export function decryptPayload(ciphertext, aesKey, iv, authTag) {
  const decipher = createDecipheriv('aes-256-gcm', aesKey, Buffer.from(iv, 'hex'));
  decipher.setAuthTag(Buffer.from(authTag, 'base64'));

  return Buffer.concat([
    decipher.update(Buffer.from(ciphertext, 'base64')),
    decipher.final()
  ]);
}

export function signData(data, privateKeyPem) {
  return sign('sha256', toBuffer(data), normalizePrivateKey(privateKeyPem)).toString('base64');
}

export function verifySignature(data, signatureBase64, publicKeyPem) {
  return verify(
    'sha256',
    toBuffer(data),
    normalizePublicKey(publicKeyPem),
    Buffer.from(signatureBase64, 'base64')
  );
}

export function createHmacSignature(secret, data) {
  return createHmac('sha256', toBuffer(secret)).update(toBuffer(data)).digest('base64');
}

export function verifyHmacSignature(secret, data, signatureBase64) {
  try {
    const expected = Buffer.from(createHmacSignature(secret, data), 'base64');
    const received = Buffer.from(signatureBase64, 'base64');

    return expected.length === received.length && timingSafeEqual(expected, received);
  } catch {
    return false;
  }
}

export function hashApiKey(apiKey) {
  return createHash('sha256').update(toBuffer(apiKey)).digest('hex');
}

export function hashPassword(password, salt) {
  return createHash('sha256')
    .update(Buffer.concat([Buffer.from(salt, 'hex'), toBuffer(password)]))
    .digest('hex');
}

export function verifyPassword(password, storedHash) {
  const [algorithm, salt, hash] = String(storedHash).split(':');

  if (algorithm !== 'sha256' || !salt || !hash) {
    return false;
  }

  return hashPassword(password, salt) === hash;
}

export function generateSalt() {
  return randomBytes(16).toString('hex');
}
