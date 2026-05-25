import config from './config.js';

const LEVELS = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40
};

const currentLevel = LEVELS[config.LOG_LEVEL] ?? LEVELS.info;

function write(level, message, meta = {}) {
  if ((LEVELS[level] ?? LEVELS.info) < currentLevel) {
    return;
  }

  const { requestRef = null, ...rest } = meta;
  const entry = {
    level,
    timestamp: new Date().toISOString(),
    requestRef,
    message,
    ...rest
  };

  console.log(JSON.stringify(entry));
}

const logger = {
  debug: (message, meta) => write('debug', message, meta),
  info: (message, meta) => write('info', message, meta),
  warn: (message, meta) => write('warn', message, meta),
  error: (message, meta) => write('error', message, meta)
};

export default logger;
