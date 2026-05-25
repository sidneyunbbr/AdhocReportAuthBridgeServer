/**
 * Module purpose:
 * Initializes and manages SQLite persistence used by the JavaScript integration server.
 * This module now uses repository-level shared-data so multiple language servers can reuse
 * the same test dataset and replay-protection storage.
 */
import Database from 'better-sqlite3';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// Resolves module directory in ESM context.
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Shared dataset directory (repository-level) used by all integration server implementations.
const sharedDataDirectory = path.resolve(__dirname, '..', '..', '..', '..', '..', 'shared-data');
const databasePath = path.join(sharedDataDirectory, 'authbridge-shared.db');

fs.mkdirSync(sharedDataDirectory, { recursive: true });

const db = new Database(databasePath);

// WAL mode gives better concurrent read/write behavior for local usage.
db.pragma('journal_mode = WAL');

function isResetOnStartEnabled() {
  return String(process.env.AUTHBRIDGE_RESET_SHARED_DATA_ON_START || 'false').toLowerCase() === 'true';
}

function createSchema() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS replay_requests (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      client_id TEXT NOT NULL,
      request_id TEXT NOT NULL,
      request_timestamp_utc TEXT NOT NULL,
      created_at_utc TEXT NOT NULL,
      expires_at_utc TEXT NOT NULL,
      UNIQUE(client_id, request_id)
    );

    CREATE TABLE IF NOT EXISTS external_auth_users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT,
      external_user_id TEXT,
      password_plain TEXT NOT NULL,
      email TEXT,
      full_name TEXT,
      is_enabled INTEGER NOT NULL DEFAULT 1,
      UNIQUE(username),
      UNIQUE(external_user_id)
    );
  `);
}

function resetDataIfRequested() {
  if (!isResetOnStartEnabled()) {
    return;
  }

  db.exec(`
    DELETE FROM replay_requests;
    DELETE FROM external_auth_users;
  `);
}

function seedExternalUsersIfEmpty() {
  const countRow = db.prepare('SELECT COUNT(1) AS count FROM external_auth_users;').get();
  if ((countRow?.count ?? 0) > 0) {
    return;
  }

  const seedUsers = [
    {
      username: 'external.user',
      external_user_id: 'external-user-001',
      password_plain: 'external.pass',
      email: 'external.user@example.com',
      full_name: 'External User',
      is_enabled: 1
    },
    {
      username: 'manuela',
      external_user_id: 'external-user-002',
      password_plain: 'manuela.pass',
      email: 'manuela@example.com',
      full_name: 'Manuela',
      is_enabled: 1
    },
    {
      username: 'magda',
      external_user_id: 'external-user-003',
      password_plain: 'magda.pass',
      email: 'magda@example.com',
      full_name: 'Magda',
      is_enabled: 1
    }
  ];

  const insertSeed = db.prepare(`
    INSERT INTO external_auth_users (
      username,
      external_user_id,
      password_plain,
      email,
      full_name,
      is_enabled
    ) VALUES (
      @username,
      @external_user_id,
      @password_plain,
      @email,
      @full_name,
      @is_enabled
    );
  `);

  const transaction = db.transaction((rows) => {
    for (const row of rows) {
      insertSeed.run(row);
    }
  });

  transaction(seedUsers);
}

createSchema();
resetDataIfRequested();
seedExternalUsersIfEmpty();

const insertReplayStatement = db.prepare(`
  INSERT INTO replay_requests (
    client_id,
    request_id,
    request_timestamp_utc,
    created_at_utc,
    expires_at_utc
  ) VALUES (
    @clientId,
    @requestId,
    @requestTimestampUtc,
    @createdAtUtc,
    @expiresAtUtc
  );
`);

const selectReplayStatement = db.prepare(`
  SELECT id
  FROM replay_requests
  WHERE client_id = ?
    AND request_id = ?
  LIMIT 1;
`);

const cleanupReplayStatement = db.prepare(`
  DELETE FROM replay_requests
  WHERE expires_at_utc <= ?;
`);

const selectUserByUsernameStatement = db.prepare(`
  SELECT
    id,
    username,
    external_user_id AS externalUserId,
    password_plain AS password,
    email,
    full_name AS fullName,
    is_enabled AS isEnabled
  FROM external_auth_users
  WHERE username = ?
  LIMIT 1;
`);

const selectUserByExternalIdStatement = db.prepare(`
  SELECT
    id,
    username,
    external_user_id AS externalUserId,
    password_plain AS password,
    email,
    full_name AS fullName,
    is_enabled AS isEnabled
  FROM external_auth_users
  WHERE external_user_id = ?
  LIMIT 1;
`);

export function findReplay(clientId, requestId) {
  return selectReplayStatement.get(clientId, requestId) ?? null;
}

// Inserts replay marker for processed secure requests.
export function saveReplay({ clientId, requestId, requestTimestampUtc, createdAtUtc, expiresAtUtc }) {
  return insertReplayStatement.run({
    clientId,
    requestId,
    requestTimestampUtc,
    createdAtUtc,
    expiresAtUtc
  });
}

export function cleanupExpiredReplays(referenceUtcIso) {
  return cleanupReplayStatement.run(referenceUtcIso);
}

export function findExternalAuthUserByUsername(username) {
  return selectUserByUsernameStatement.get(username) ?? null;
}

export function findExternalAuthUserByExternalId(externalUserId) {
  return selectUserByExternalIdStatement.get(externalUserId) ?? null;
}

// Exposes DB path for diagnostics and troubleshooting documentation.
export function getDatabasePath() {
  return databasePath;
}
