import path from 'node:path';
import Database from 'better-sqlite3';
import config from '../config.js';

export let db = null;

function resolveDbPath(dbPath) {
  return dbPath === ':memory:' ? dbPath : path.resolve(process.cwd(), dbPath);
}

export function initializeDb(dbPath = config.DB_PATH, { force = false } = {}) {
  const resolvedPath = resolveDbPath(dbPath);

  if (db && !force) {
    return db;
  }

  closeDb();
  db = new Database(resolvedPath);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  return db;
}

export function getDb() {
  if (!db) {
    return initializeDb();
  }

  return db;
}

export function closeDb() {
  if (db) {
    db.close();
    db = null;
  }
}

export function getActiveKey(now = new Date().toISOString()) {
  return getDb()
    .prepare(`
      SELECT * FROM server_keys
      WHERE is_active = 1 AND valid_from <= ? AND valid_until >= ?
      ORDER BY created_at DESC
      LIMIT 1
    `)
    .get(now, now);
}

export function getApiClient(clientId) {
  return getDb().prepare('SELECT * FROM api_clients WHERE client_id = ? LIMIT 1').get(clientId);
}

export function getApiClientByHash(apiKeyHash) {
  return getDb()
    .prepare('SELECT * FROM api_clients WHERE api_key_hash = ? AND is_active = 1 LIMIT 1')
    .get(apiKeyHash);
}

export function checkReplay(clientId, requestId) {
  const row = getDb()
    .prepare(
      'SELECT 1 FROM replay_cache WHERE client_id = ? AND request_id = ? AND expires_at > ? LIMIT 1'
    )
    .get(clientId, requestId, new Date().toISOString());

  return Boolean(row);
}

export function insertReplay(clientId, requestId, ttlSeconds = config.REPLAY_TTL_SECONDS) {
  const seenAt = new Date();
  const expiresAt = new Date(seenAt.getTime() + ttlSeconds * 1000);

  getDb()
    .prepare(
      'INSERT INTO replay_cache (client_id, request_id, seen_at, expires_at) VALUES (?, ?, ?, ?)'
    )
    .run(clientId, requestId, seenAt.toISOString(), expiresAt.toISOString());
}

export function cleanExpiredReplays() {
  return getDb()
    .prepare('DELETE FROM replay_cache WHERE expires_at <= ?')
    .run(new Date().toISOString());
}

export function findUser(username) {
  return getDb()
    .prepare('SELECT * FROM local_users WHERE username = ? AND is_active = 1 LIMIT 1')
    .get(username);
}

export function insertAuditLog(entry) {
  const detail =
    typeof entry.detail === 'string' || entry.detail == null
      ? entry.detail
      : JSON.stringify(entry.detail);

  getDb()
    .prepare(
      `
        INSERT INTO audit_log (request_ref, client_id, event_type, status, detail)
        VALUES (?, ?, ?, ?, ?)
      `
    )
    .run(entry.requestRef ?? null, entry.clientId ?? null, entry.eventType, entry.status, detail ?? null);
}
