/**
 * Module purpose:
 * Maintains in-memory development key material for secure validation flow.
 * This reference implementation uses runtime-generated keys to demonstrate protocol behavior.
 */
import { createPublicKey, generateKeyPairSync } from 'node:crypto';
import { getSecurityConfig } from '../config/securityConfig.js';
import { fromBase64Url, toBase64Url } from './base64url.js';

const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');
const serverEncryptionKeys = generateKeyPairSync('x25519');
const serverSignatureKeys = generateKeyPairSync('ed25519');
const demoClientSignatureKeys = generateKeyPairSync('ed25519');

const defaultIds = {
  encryptionKeyId: process.env.AUTHBRIDGE_ENCRYPTION_KEY_ID || 'enc-dev-2026-05',
  serverSignatureKeyId: process.env.AUTHBRIDGE_SERVER_SIGNATURE_KEY_ID || 'bridge-sig-dev-2026-05',
  demoClientSignatureKeyId: process.env.AUTHBRIDGE_DEMO_CLIENT_SIGNATURE_KEY_ID || 'client-sig-2026-05'
};

function exportRawPublicKey(publicKey) {
  const der = publicKey.export({ format: 'der', type: 'spki' });
  return Buffer.from(der).subarray(Buffer.from(der).length - 32);
}

function toX25519PublicKey(rawPublicKeyBytes) {
  if (!Buffer.isBuffer(rawPublicKeyBytes) || rawPublicKeyBytes.length !== 32) {
	throw new Error('X25519 public key must be 32 bytes.');
  }

  const spki = Buffer.concat([X25519_SPKI_PREFIX, rawPublicKeyBytes]);
  return createPublicKey({ key: spki, format: 'der', type: 'spki' });
}

export function getServerEncryptionKeyPair() {
  return serverEncryptionKeys;
}

export function getServerSignatureKeyPair() {
  return serverSignatureKeys;
}

export function getClientPublicSigningKeyById(signatureKeyId) {
  if (signatureKeyId === defaultIds.demoClientSignatureKeyId) {
	return demoClientSignatureKeys.publicKey;
  }

  return null;
}

export function getServerEncryptionPublicKeyBase64Url() {
  return toBase64Url(exportRawPublicKey(serverEncryptionKeys.publicKey));
}

export function getServerSignaturePublicKeyBase64Url() {
  return toBase64Url(exportRawPublicKey(serverSignatureKeys.publicKey));
}

export function importClientEphemeralPublicKey(base64UrlValue) {
	const rawBytes = fromBase64Url(base64UrlValue);

  if (rawBytes.length === 32) {
	return toX25519PublicKey(rawBytes);
  }

  // Accept DER SPKI as fallback for interoperability tests.
  return createPublicKey({ key: rawBytes, format: 'der', type: 'spki' });
}

export function getKeyDiscoveryPayload() {
  const config = getSecurityConfig();

  return {
	protocolVersion: config.secureProtocolVersion,
	serverTimeUtc: new Date().toISOString(),
	encryption: {
	  kty: 'OKP',
	  crv: config.keyAgreementCurve,
	  keyId: defaultIds.encryptionKeyId,
	  publicKey: getServerEncryptionPublicKeyBase64Url(),
	  notBeforeUtc: '2026-01-01T00:00:00Z',
	  notAfterUtc: '2027-01-01T00:00:00Z'
	},
	signature: {
	  kty: 'OKP',
	  crv: config.signatureAlgorithm,
	  keyId: defaultIds.serverSignatureKeyId,
	  publicKey: getServerSignaturePublicKeyBase64Url()
	},
	requirements: {
	  maxClockSkewSeconds: config.maxClockSkewSeconds,
	  requestIdTtlSeconds: config.replayTtlSeconds,
	  contentEncryption: config.contentEncryption,
	  kdf: config.kdfAlgorithm
	}
  };
}

export function getKeyIdentifiers() {
  return {
	encryptionKeyId: defaultIds.encryptionKeyId,
	serverSignatureKeyId: defaultIds.serverSignatureKeyId,
	demoClientSignatureKeyId: defaultIds.demoClientSignatureKeyId
  };
}

// Development helper for smoke tests and examples.
export function getDemoClientSigningPrivateKey() {
  return demoClientSignatureKeys.privateKey;
}

// Development helper for smoke tests and examples.
export function getDemoClientSigningPublicKeyBase64Url() {
  return toBase64Url(exportRawPublicKey(demoClientSignatureKeys.publicKey));
}
