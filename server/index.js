import config from './config.js';
import logger from './logger.js';
import createApp from './app.js';
import { closeDb, initializeDb } from './db/index.js';

initializeDb(config.DB_PATH, { force: true });
const app = createApp(config);

const server = app.listen(config.PORT, () => {
  logger.info('AdhocReportAuthBridgeServer started.', {
    requestRef: 'startup',
    port: config.PORT,
    env: config.NODE_ENV,
    dbPath: config.DB_PATH
  });
});

async function shutdown(signal) {
  logger.info('Shutdown signal received.', { requestRef: 'shutdown', signal });
  server.close(() => {
    closeDb();
    logger.info('Server stopped.', { requestRef: 'shutdown' });
    process.exit(0);
  });
}

process.on('SIGINT', () => {
  shutdown('SIGINT').catch(() => {
    process.exit(1);
  });
});

process.on('SIGTERM', () => {
  shutdown('SIGTERM').catch(() => {
    process.exit(1);
  });
});
