/**
 * Module purpose:
 * Provides cryptographic operations for secure envelope processing:
 * key agreement, HKDF derivation, AES-GCM decrypt/encrypt.
 */
import { createCipheriv, createDecipheriv, diffieHellman, hkdfSync, randomBytes } from 'node:crypto';
import { getSecurityConfig } from '../config/securityConfig.js';
import { fromBase64Url, toBase64Url } from './base64url.js';
import { getServerEncryptionPrivateKeyById, importClientEphemeralPublicKey } from './keyStore.js';

// Used by secureValidationService: derives AES key from request key material and keyId.
export function deriveRequestKey(envelope) {
  const config = getSecurityConfig();
  const clientEphemeralPublicKey = importClientEphemeralPublicKey(envelope.clientEphemeralPublicKey);
  const serverEncryptionPrivateKey = getServerEncryptionPrivateKeyById(envelope.keyId);

  if (!serverEncryptionPrivateKey) {
    throw new Error(`Server encryption key '${envelope.keyId}' was not found.`);
  }

  const sharedSecret = diffieHellman({
    privateKey: serverEncryptionPrivateKey,
    publicKey: clientEphemeralPublicKey
  });

  return Buffer.from(
    hkdfSync(
      'sha256',
      sharedSecret,
      Buffer.from(envelope.requestId, 'utf8'),
      Buffer.from(config.kdfInfo, 'utf8'),
      32
    )
  );
}

// Used by secureValidationService: decrypts request payload after signature/key checks pass.
export function decryptRequestPayload(envelope, derivedKey) {
  const nonce = fromBase64Url(envelope.nonce);
  const aad = fromBase64Url(envelope.aad);
  const ciphertext = fromBase64Url(envelope.ciphertext);
  const tag = fromBase64Url(envelope.tag);

  const decipher = createDecipheriv('aes-256-gcm', derivedKey, nonce);
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);

  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return JSON.parse(plaintext.toString('utf8'));
}

// Used by secureValidationService: encrypts business response payload into contract envelope fields.
export function encryptResponsePayload(responsePayload, derivedKey, aadObject) {
  const nonceBytes = randomBytes(12);
  const aadBytes = Buffer.from(JSON.stringify(aadObject), 'utf8');
  const plaintext = Buffer.from(JSON.stringify(responsePayload), 'utf8');

  const cipher = createCipheriv('aes-256-gcm', derivedKey, nonceBytes);
  cipher.setAAD(aadBytes);

  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();

  return {
    nonce: toBase64Url(nonceBytes),
    aad: toBase64Url(aadBytes),
    ciphertext: toBase64Url(ciphertext),
    tag: toBase64Url(tag)
  };
}

// Helper to keep AAD shape stable between service and clients (kept for future reuse).
export function buildResponseAad(responseEnvelope) {
  return {
	protocolVersion: responseEnvelope.protocolVersion,
	requestId: responseEnvelope.requestId,
	responseId: responseEnvelope.responseId,
	timestampUtc: responseEnvelope.timestampUtc,
	signatureKeyId: responseEnvelope.signatureKeyId
  };
}
