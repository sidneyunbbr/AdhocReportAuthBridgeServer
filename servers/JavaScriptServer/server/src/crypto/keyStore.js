/**
 * Module purpose:
 * Maintains persisted development key material for secure validation flow.
 * Key records are stored in shared-data so examples/tests are reproducible and key rotation
 * (active + previous) can be demonstrated consistently.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createPrivateKey, createPublicKey, generateKeyPairSync } from 'node:crypto';
import { getSecurityConfig } from '../config/securityConfig.js';
import { fromBase64Url, toBase64Url } from './base64url.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const KEYRING_REQUIRED_ARRAY_FIELDS = ['encryptionKeys', 'serverSignatureKeys', 'clientSigningKeys'];

// Repository-level shared-data path so all language implementations can reuse key material.
const sharedDataDirectory = path.resolve(__dirname, '..', '..', '..', '..', '..', 'shared-data');
const keyringPath = path.join(sharedDataDirectory, 'authbridge-keyring.json');

// Ensures keyring storage folder exists before load/create operations.
function ensureSharedDataDirectory() {
  fs.mkdirSync(sharedDataDirectory, { recursive: true });
}

// Extracts raw 32-byte public key from DER SPKI representation.
function exportRawPublicKey(publicKey) {
  const der = publicKey.export({ format: 'der', type: 'spki' });
  return Buffer.from(der).subarray(Buffer.from(der).length - 32);
}

// Rebuilds Node PublicKey object from raw X25519 bytes received in contract payloads.
function toX25519PublicKey(rawPublicKeyBytes) {
  if (!Buffer.isBuffer(rawPublicKeyBytes) || rawPublicKeyBytes.length !== 32) {
    throw new Error('X25519 public key must be 32 bytes.');
  }

  const spki = Buffer.concat([X25519_SPKI_PREFIX, rawPublicKeyBytes]);
  return createPublicKey({ key: spki, format: 'der', type: 'spki' });
}

// Rebuilds Node PublicKey object from raw Ed25519 bytes used in signature verification.
function toEd25519PublicKey(rawPublicKeyBytes) {
  if (!Buffer.isBuffer(rawPublicKeyBytes) || rawPublicKeyBytes.length !== 32) {
    throw new Error('Ed25519 public key must be 32 bytes.');
  }

  const spki = Buffer.concat([ED25519_SPKI_PREFIX, rawPublicKeyBytes]);
  return createPublicKey({ key: spki, format: 'der', type: 'spki' });
}

// Creates one encryption key record for keyring persistence and rotation tracking.
function generateX25519Record(keyId, status, notBeforeUtc, notAfterUtc) {
  const pair = generateKeyPairSync('x25519');
  return createKeyRecordFromPair(pair, keyId, status, { notBeforeUtc, notAfterUtc });
}

// Creates one signing key record for keyring persistence and rotation tracking.
function generateEd25519Record(keyId, status) {
  const pair = generateKeyPairSync('ed25519');
  return createKeyRecordFromPair(pair, keyId, status);
}

// Builds a persisted key record from generated key pair plus extra metadata.
function createKeyRecordFromPair(pair, keyId, status, extra = {}) {
  return {
    keyId,
    status,
    privateKeyPem: pair.privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
    publicKey: toBase64Url(exportRawPublicKey(pair.publicKey)),
    ...extra
  };
}

// Default keyring used on first startup. Contains active + previous keys to demonstrate rotation.
function createDefaultKeyring() {
  const now = new Date();
  const currentFrom = new Date(now.getTime() - 24 * 60 * 60 * 1000).toISOString();
  const currentTo = new Date(now.getTime() + 180 * 24 * 60 * 60 * 1000).toISOString();
  const previousFrom = new Date(now.getTime() - 365 * 24 * 60 * 60 * 1000).toISOString();
  const previousTo = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000).toISOString();

  return {
    version: 1,
    createdAtUtc: new Date().toISOString(),
    encryptionKeys: [
      generateX25519Record('enc-dev-2026-05', 'active', currentFrom, currentTo),
      generateX25519Record('enc-dev-2026-04', 'previous', previousFrom, previousTo)
    ],
    serverSignatureKeys: [
      generateEd25519Record('bridge-sig-dev-2026-05', 'active'),
      generateEd25519Record('bridge-sig-dev-2026-04', 'previous')
    ],
    clientSigningKeys: [
      generateEd25519Record('client-sig-2026-05', 'active')
    ]
  };
}

// Loads an existing keyring from shared-data or creates a new one when missing.
function loadOrCreateKeyring() {
  ensureSharedDataDirectory();

  if (fs.existsSync(keyringPath)) {
    const content = fs.readFileSync(keyringPath, 'utf8');
    const parsed = JSON.parse(content);

    if (!isValidKeyring(parsed)) {
      throw new Error('Invalid keyring file format.');
    }

    return parsed;
  }

  const created = createDefaultKeyring();
  fs.writeFileSync(keyringPath, JSON.stringify(created, null, 2), 'utf8');
  return created;
}

// Minimal persisted-keyring shape check used on startup.
function isValidKeyring(parsed) {
  return KEYRING_REQUIRED_ARRAY_FIELDS.every((fieldName) => Array.isArray(parsed[fieldName]));
}

const keyring = loadOrCreateKeyring();

// Helper to obtain active key from one key collection (fallback: first record).
function findActive(records) {
  return records.find((x) => x.status === 'active') ?? records[0] ?? null;
}

// Helper to retrieve a key record by keyId.
function findById(records, keyId) {
  return records.find((x) => x.keyId === keyId) ?? null;
}

// Resolves private key from a key list by keyId.
function resolvePrivateKeyById(records, keyId) {
  const record = findById(records, keyId);
  return record ? toPrivateKey(record.privateKeyPem) : null;
}

// Returns keyId values from a key record list.
function listKeyIds(records) {
  return records.map((x) => x.keyId);
}

// Converts persisted PEM private key to Node KeyObject for crypto operations.
function toPrivateKey(pem) {
  return createPrivateKey({ key: pem, format: 'pem', type: 'pkcs8' });
}

// Used by secureEnvelopeCrypto. Resolves server private encryption key by envelope keyId.
export function getServerEncryptionPrivateKeyById(keyId) {
  return resolvePrivateKeyById(keyring.encryptionKeys, keyId);
}

// Used by secureValidationService to sign response envelope with selected server key.
export function getServerSignaturePrivateKeyById(keyId) {
  return resolvePrivateKeyById(keyring.serverSignatureKeys, keyId);
}

// Used by secureValidationService when selecting current server signing key for responses.
export function getActiveServerSignatureKeyRecord() {
  return findActive(keyring.serverSignatureKeys);
}

// Used by secureValidationService to verify inbound request signatures from customer server.
export function getClientPublicSigningKeyById(signatureKeyId) {
  const record = findById(keyring.clientSigningKeys, signatureKeyId);
  if (!record) {
    return null;
  }

  return toEd25519PublicKey(fromBase64Url(record.publicKey));
}

// Exposed for examples/tests to know which client key is currently active.
export function getActiveClientSigningKeyRecord() {
  return findActive(keyring.clientSigningKeys);
}

// Exposed for examples/tests to sign secure request envelopes.
export function getActiveClientSigningPrivateKey() {
  const active = getActiveClientSigningKeyRecord();
  return active ? toPrivateKey(active.privateKeyPem) : null;
}

// List of accepted encryption key IDs (active + previous) used for rotation compatibility.
export function getAcceptedEncryptionKeyIds() {
  return listKeyIds(keyring.encryptionKeys);
}

// List of accepted server response signature key IDs.
export function getAcceptedServerSignatureKeyIds() {
  return listKeyIds(keyring.serverSignatureKeys);
}

// Fast check used before decryption to reject unknown encryption keys.
export function isSupportedEncryptionKeyId(keyId) {
  return getAcceptedEncryptionKeyIds().includes(keyId);
}

// Fast check used before signature verification to reject unknown client key IDs.
export function isSupportedClientSignatureKeyId(keyId) {
  return keyring.clientSigningKeys.some((x) => x.keyId === keyId);
}

// Converts client ephemeral key (Base64Url) into a Node PublicKey for ECDH operation.
export function importClientEphemeralPublicKey(base64UrlValue) {
  const rawBytes = fromBase64Url(base64UrlValue);

  if (rawBytes.length === 32) {
    return toX25519PublicKey(rawBytes);
  }

  // Accept DER SPKI as fallback for interoperability tests.
  return createPublicKey({ key: rawBytes, format: 'der', type: 'spki' });
}

// Used by /api/external-auth/keys route to publish key-discovery payload.
export function getKeyDiscoveryPayload() {
  const config = getSecurityConfig();
  const activeEnc = findActive(keyring.encryptionKeys);
  const activeSig = findActive(keyring.serverSignatureKeys);

  return {
    protocolVersion: config.secureProtocolVersion,
    serverTimeUtc: new Date().toISOString(),
    encryption: {
      kty: 'OKP',
      crv: config.keyAgreementCurve,
      keyId: activeEnc.keyId,
      publicKey: activeEnc.publicKey,
      notBeforeUtc: activeEnc.notBeforeUtc,
      notAfterUtc: activeEnc.notAfterUtc
    },
    signature: {
      kty: 'OKP',
      crv: config.signatureAlgorithm,
      keyId: activeSig.keyId,
      publicKey: activeSig.publicKey
    },
    requirements: {
      maxClockSkewSeconds: config.maxClockSkewSeconds,
      requestIdTtlSeconds: config.replayTtlSeconds,
      contentEncryption: config.contentEncryption,
      kdf: config.kdfAlgorithm,
      acceptedEncryptionKeyIds: getAcceptedEncryptionKeyIds(),
      acceptedServerSignatureKeyIds: getAcceptedServerSignatureKeyIds(),
      acceptedClientSignatureKeyIds: listKeyIds(keyring.clientSigningKeys)
    }
  };
}

// Exposes keyring location to support diagnostics and customer migration guidance.
export function getDatabaseKeyringPath() {
  return keyringPath;
}

// Development helper for smoke tests and examples.
export function getDemoClientSigningPrivateKey() {
  return getActiveClientSigningPrivateKey();
}

// Development helper for smoke tests and examples.
export function getDemoClientSigningPublicKeyBase64Url() {
  const activeClient = getActiveClientSigningKeyRecord();
  return activeClient ? activeClient.publicKey : null;
}
