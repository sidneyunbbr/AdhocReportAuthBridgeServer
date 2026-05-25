import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import Database from 'better-sqlite3';
import config from '../server/config.js';

const __filename = fileURLToPath(import.meta.url);
const migrationFile = path.resolve(path.dirname(__filename), 'migrations/001_init.sql');

export function loadMigrationSql() {
  return fs.readFileSync(migrationFile, 'utf8');
}

export function applyMigration(database) {
  database.exec(loadMigrationSql());
}

export async function runMigration(dbPath = config.DB_PATH) {
  const resolvedPath = dbPath === ':memory:' ? dbPath : path.resolve(process.cwd(), dbPath);

  if (resolvedPath !== ':memory:') {
    fs.mkdirSync(path.dirname(resolvedPath), { recursive: true });
  }

  const database = new Database(resolvedPath);

  try {
    database.pragma('foreign_keys = ON');
    applyMigration(database);
  } finally {
    database.close();
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === __filename) {
  runMigration().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
}
