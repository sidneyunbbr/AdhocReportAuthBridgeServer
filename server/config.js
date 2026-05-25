import dotenv from 'dotenv';

dotenv.config();

function toInt(value, fallback) {
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function toBool(value, fallback) {
  if (value === undefined) {
    return fallback;
  }

  return String(value).toLowerCase() === 'true';
}

const config = Object.freeze({
  PORT: toInt(process.env.PORT, 3000),
  NODE_ENV: process.env.NODE_ENV || 'development',
  DB_PATH: process.env.DB_PATH || './data/authbridge.db',
  API_KEY_HEADER: process.env.API_KEY_HEADER || 'x-api-key',
  MAX_PAYLOAD_BYTES: toInt(process.env.MAX_PAYLOAD_BYTES, 65536),
  TIMESTAMP_TOLERANCE_SECONDS: toInt(process.env.TIMESTAMP_TOLERANCE_SECONDS, 300),
  REPLAY_TTL_SECONDS: toInt(process.env.REPLAY_TTL_SECONDS, 600),
  REQUIRE_HTTPS: toBool(process.env.REQUIRE_HTTPS, false),
  LOG_LEVEL: process.env.LOG_LEVEL || 'info',
  SERVER_CURVE: process.env.SERVER_CURVE || 'P-256',
  PROTOCOL_VERSION: process.env.PROTOCOL_VERSION || '1.0'
});

export default config;
