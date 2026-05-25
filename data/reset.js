import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import config from '../server/config.js';
import { runMigration } from './migrate.js';
import { runSeed } from './seed.js';

const __filename = fileURLToPath(import.meta.url);

export async function runReset(dbPath = config.DB_PATH) {
  const resolvedPath = dbPath === ':memory:' ? dbPath : path.resolve(process.cwd(), dbPath);

  if (resolvedPath !== ':memory:' && fs.existsSync(resolvedPath)) {
    fs.rmSync(resolvedPath);
  }

  await runMigration(dbPath);
  await runSeed(dbPath);
}

if (process.argv[1] && path.resolve(process.argv[1]) === __filename) {
  runReset().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
}
