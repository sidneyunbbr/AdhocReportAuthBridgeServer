import { diffieHellman, createPublicKey, randomUUID } from 'node:crypto';
import assert from 'node:assert/strict';
import config from '../config.js';
import createApp from '../app.js';
import {
  createHmacSignature,
  decryptPayload,
  deriveAesKey,
  encryptPayload,
  generateEphemeralKeyPair
} from '../crypto/index.js';
import { closeDb, getActiveKey, initializeDb, insertReplay, getDb } from '../db/index.js';
import { applyMigration } from '../../data/migrate.js';
import { DEFAULT_SEED, seedDatabase } from '../../data/seed.js';
import { buildCanonicalString } from '../routes/validateSecure.js';

export function resetTestDatabase() {
  initializeDb(':memory:', { force: true });
  applyMigration(getDb());
  seedDatabase(getDb());
}

export async function startTestServer(port = 3001) {
  const app = createApp({ ...config, PORT: port, DB_PATH: ':memory:', REQUIRE_HTTPS: false });
  const server = await new Promise((resolve) => {
    const instance = app.listen(port, () => resolve(instance));
  });

  return {
    baseUrl: `http://127.0.0.1:${port}`,
    server,
    async stop() {
      await new Promise((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      });
      closeDb();
    }
  };
}

export function buildValidEnvelope(overrides = {}) {
  const activeKey = getActiveKey();
  assert.ok(activeKey, 'Active key must exist for test envelope creation.');

  const requestId = overrides.requestId ?? randomUUID();
  const timestamp = overrides.timestamp ?? Date.now();
  const credentials = overrides.credentials ?? {
    username: 'user1',
    password: 'password1'
  };
  const apiKey = overrides.apiKey ?? DEFAULT_SEED.apiKey;
  const clientId = overrides.clientId ?? DEFAULT_SEED.clientId;
  const keyId = overrides.keyId ?? activeKey.key_id;

  const clientKeyPair = generateEphemeralKeyPair();
  const clientPublicKeyDer = clientKeyPair.publicKey.export({ format: 'der', type: 'spki' });
  const clientPublicKey = Buffer.from(clientPublicKeyDer).toString('base64');
  const serverPublicKey = createPublicKey(activeKey.public_key_pem);
  const sharedSecret = diffieHellman({
    privateKey: clientKeyPair.privateKey,
    publicKey: serverPublicKey
  });
  const aesKey = deriveAesKey(sharedSecret, 'authbridge-aes-key', requestId);
  const encryptedPayload = encryptPayload(JSON.stringify(credentials), aesKey);

  const envelope = {
    keyId,
    clientId,
    requestId,
    timestamp,
    clientPublicKey,
    encryptedPayload: encryptedPayload.ciphertext,
    iv: encryptedPayload.iv,
    authTag: encryptedPayload.authTag
  };
  envelope.signature = createHmacSignature(apiKey, buildCanonicalString(envelope));

  if (overrides.signature) {
    envelope.signature = overrides.signature;
  }
  if (overrides.encryptedPayload) {
    envelope.encryptedPayload = overrides.encryptedPayload;
  }
  if (overrides.iv) {
    envelope.iv = overrides.iv;
  }
  if (overrides.authTag) {
    envelope.authTag = overrides.authTag;
  }

  return {
    envelope,
    aesKey,
    decryptResponse(payload) {
      return JSON.parse(
        decryptPayload(payload.encryptedResult, aesKey, payload.iv, payload.authTag).toString('utf8')
      );
    }
  };
}

export function seedReplay(clientId, requestId) {
  insertReplay(clientId, requestId, 60);
}
