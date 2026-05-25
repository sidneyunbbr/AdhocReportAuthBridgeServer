import path from 'node:path';
import { fileURLToPath } from 'node:url';
import Database from 'better-sqlite3';
import { generateKeyPairSync } from 'node:crypto';
import config from '../server/config.js';
import { generateSalt, hashApiKey, hashPassword } from '../server/crypto/index.js';

const __filename = fileURLToPath(import.meta.url);

export const DEFAULT_SEED = Object.freeze({
  keyId: 'server-key-001',
  clientId: 'test-client-001',
  apiKey: 'test-api-key-secret-001'
});

function buildPasswordHash(password) {
  const salt = generateSalt();
  return `sha256:${salt}:${hashPassword(password, salt)}`;
}

export function seedDatabase(database) {
  const now = new Date();
  const validUntil = new Date(now);
  validUntil.setFullYear(validUntil.getFullYear() + 1);

  const { publicKey, privateKey } = generateKeyPairSync('ec', {
    namedCurve: 'P-256',
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });

  database.prepare('DELETE FROM replay_cache').run();

  database
    .prepare(
      `
        INSERT INTO server_keys (
          key_id, algorithm, public_key_pem, private_key_pem, valid_from, valid_until, is_active
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(key_id) DO UPDATE SET
          algorithm = excluded.algorithm,
          public_key_pem = excluded.public_key_pem,
          private_key_pem = excluded.private_key_pem,
          valid_from = excluded.valid_from,
          valid_until = excluded.valid_until,
          is_active = excluded.is_active
      `
    )
    .run(
      DEFAULT_SEED.keyId,
      'EC-P256',
      publicKey,
      privateKey,
      now.toISOString(),
      validUntil.toISOString(),
      1
    );

  database
    .prepare(
      `
        INSERT INTO api_clients (client_id, api_key_hash, name, is_active)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(client_id) DO UPDATE SET
          api_key_hash = excluded.api_key_hash,
          name = excluded.name,
          is_active = excluded.is_active
      `
    )
    .run(
      DEFAULT_SEED.clientId,
      hashApiKey(DEFAULT_SEED.apiKey),
      'Test Client',
      1
    );

  const users = [
    ['admin', buildPasswordHash('admin123'), 'admin'],
    ['user1', buildPasswordHash('password1'), 'user']
  ];

  const statement = database.prepare(
    `
      INSERT INTO local_users (username, password_hash, role, is_active)
      VALUES (?, ?, ?, ?)
      ON CONFLICT(username) DO UPDATE SET
        password_hash = excluded.password_hash,
        role = excluded.role,
        is_active = excluded.is_active
    `
  );

  for (const [username, passwordHash, role] of users) {
    statement.run(username, passwordHash, role, 1);
  }
}

export async function runSeed(dbPath = config.DB_PATH) {
  const resolvedPath = dbPath === ':memory:' ? dbPath : path.resolve(process.cwd(), dbPath);
  const database = new Database(resolvedPath);

  try {
    database.pragma('foreign_keys = ON');
    seedDatabase(database);
  } finally {
    database.close();
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === __filename) {
  runSeed().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
}
