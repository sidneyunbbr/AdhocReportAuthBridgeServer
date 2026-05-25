/**
 * Script purpose:
 * Resets and reseeds shared integration test data by bootstrapping SQLite with
 * AUTHBRIDGE_RESET_SHARED_DATA_ON_START=true in a one-off execution context.
 */
import process from 'node:process';

// sqlite bootstrap reads this flag on import and performs delete+seed in one run.
process.env.AUTHBRIDGE_RESET_SHARED_DATA_ON_START = 'true';

// Dynamic import executes initialization side effects without duplicating schema/seed logic here.
await import('../server/src/data/sqlite.js');

console.log('[reseed-shared-data] Shared test data reset/reseed completed.');
