/**
 * Example purpose:
 * Demonstrates a full secure round-trip client flow against JavaScriptServer:
 * 1) key discovery, 2) request sign+encrypt, 3) secure validation call,
 * 4) response signature verification, 5) response decrypt.
 */
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

const API_BASE_URL = process.env.AUTHBRIDGE_BASE_URL || 'http://localhost:3000';
const SHARED_API_KEY = process.env.AUTHBRIDGE_REQUEST_API_KEY || 'ADLK40308$$55DLD-DKDLLKDLL23093DL';
const CLIENT_SIGNATURE_KEY_ID = process.env.AUTHBRIDGE_CLIENT_SIGNATURE_KEY_ID || 'client-sig-2026-05';

const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

// Keep encoding helpers aligned with server/src/crypto/base64url.js contract behavior.
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

// SPKI conversion mirrors server keyStore import helpers for compatibility.
function toX25519PublicKey(rawBytes) {
  return createPublicKey({ key: Buffer.concat([X25519_SPKI_PREFIX, rawBytes]), format: 'der', type: 'spki' });
}

// Ed25519 conversion is required to verify signature over encrypted response envelope.
function toEd25519PublicKey(rawBytes) {
  return createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, rawBytes]), format: 'der', type: 'spki' });
}

function exportRawX25519PublicKey(publicKey) {
  const der = publicKey.export({ format: 'der', type: 'spki' });
  return Buffer.from(der).subarray(Buffer.from(der).length - 32);
}

// Canonical signing input must match server/src/crypto/signature.js field order exactly.
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

// Canonical response signing input used for server authenticity verification.
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

// HKDF parameters must match server/src/crypto/secureEnvelopeCrypto.js.
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

async function main() {
  // Step 1: discover active server keys/protocol so request uses current rotation window.
  const keyDiscoveryResponse = await fetch(`${API_BASE_URL}/api/external-auth/keys`);
  if (!keyDiscoveryResponse.ok) {
    throw new Error(`Key discovery failed with status ${keyDiscoveryResponse.status}`);
  }

  const keys = await keyDiscoveryResponse.json();

  // Demo client private key comes from server keyStore only for local interoperability tests.
  const clientSigningKeys = await import('../server/src/crypto/keyStore.js');
  const clientSigningPrivateKey = clientSigningKeys.getDemoClientSigningPrivateKey();

  // X25519 + diffieHellman is the runtime-supported path in Node for this flow.
  const clientKeyPair = generateKeyPairSync('x25519');
  const serverPublicKey = toX25519PublicKey(fromBase64Url(keys.encryption.publicKey));
  const sharedSecret = diffieHellman({
    privateKey: clientKeyPair.privateKey,
    publicKey: serverPublicKey
  });

  const requestId = crypto.randomUUID();
  const timestampUtc = new Date().toISOString();
  const derivedKey = deriveKey(sharedSecret, requestId);

  const aadObject = {
    protocolVersion: keys.protocolVersion,
    clientId: 'customer-a-prod',
    requestId,
    timestampUtc,
    keyId: keys.encryption.keyId,
    signatureKeyId: CLIENT_SIGNATURE_KEY_ID
  };

  const plaintext = {
    username: 'external.user',
    externalUserId: null,
    password: 'external.pass',
    correlationId: `corr-${requestId}`,
    requestedScopes: ['validate-login']
  };

  // AES-GCM uses AAD to bind envelope metadata with encrypted content.
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
    signatureKeyId: CLIENT_SIGNATURE_KEY_ID,
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

  const signatureInput = buildRequestSigningInput(envelope);
  envelope.signature = toBase64Url(sign(null, signatureInput, clientSigningPrivateKey));

  // Step 2: call secure endpoint using same shared API key configured in AdhocReport appsettings.
  const validateResponse = await fetch(`${API_BASE_URL}/api/external-auth/validate-secure`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Bridge-Api-Key': SHARED_API_KEY,
      'X-AuthBridge-Protocol': keys.protocolVersion,
      'X-Correlation-Id': plaintext.correlationId
    },
    body: JSON.stringify(envelope)
  });

  const responseEnvelope = await validateResponse.json();

  if (!validateResponse.ok) {
    console.error('Secure validation failed:', responseEnvelope);
    process.exit(1);
  }

  // Step 3: verify server signature before decrypting payload.
  const serverSignaturePublicKey = toEd25519PublicKey(fromBase64Url(keys.signature.publicKey));
  const responseSignatureInput = buildResponseSigningInput(responseEnvelope);
  const responseSignatureValid = verify(
    null,
    responseSignatureInput,
    serverSignaturePublicKey,
    fromBase64Url(responseEnvelope.signature)
  );

  if (!responseSignatureValid) {
    throw new Error('Response signature verification failed.');
  }

  // Step 4: decrypt secure response with same derived request key.
  const responseDecipher = createDecipheriv(
    'aes-256-gcm',
    derivedKey,
    fromBase64Url(responseEnvelope.nonce)
  );
  responseDecipher.setAAD(fromBase64Url(responseEnvelope.aad));
  responseDecipher.setAuthTag(fromBase64Url(responseEnvelope.tag));

  const decryptedResponseBytes = Buffer.concat([
    responseDecipher.update(fromBase64Url(responseEnvelope.ciphertext)),
    responseDecipher.final()
  ]);

  const decryptedResponse = JSON.parse(decryptedResponseBytes.toString('utf8'));

  console.log('Secure round-trip succeeded. Decrypted response payload:');
  console.log(JSON.stringify(decryptedResponse, null, 2));
}

main().catch((error) => {
  console.error('Secure round-trip example failed:', error);
  process.exit(1);
});
