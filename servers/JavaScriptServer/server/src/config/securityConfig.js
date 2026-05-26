/**
 * Module purpose:
 * Centralizes security-related runtime configuration for the secure endpoint flow.
 * It translates environment variables into normalized policy values consumed by validators.
 */
const DEFAULT_PROTOCOL_VERSION = '1.0';
const DEFAULT_SECURE_PROTOCOL_VERSION = '2.0';
const DEFAULT_CLOCK_SKEW_SECONDS = 300;
const DEFAULT_REPLAY_TTL_SECONDS = 600;

// Converts environment flags to booleans with a fallback default.
function parseBoolean(value, fallback) {
  if (value === undefined || value === null) {
	return fallback;
  }

  return String(value).toLowerCase() === 'true';
}

// Converts numeric environment values safely with fallback defaults.
function parseNumber(value, fallback) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

// Centralized security policy used by request validators and routes.
// This is the single point where AUTHBRIDGE_* environment variables are read and applied.
// In the current simplified phase, missing variables do not block startup because fallbacks are used.
// Clients can choose one of two paths:
// 1) Define environment variables in the Node.js host to align with caller applications; or
// 2) Keep variables undefined and adjust fallback values in this function to match their ecosystem defaults.
// For API key flow specifically:
// - AUTHBRIDGE_REQUEST_API_KEY_HEADER_NAME falls back to 'x-bridge-api-key'.
// - AUTHBRIDGE_REQUEST_API_KEY falls back to '' (empty), which allows startup but can deny requests when API key enforcement is enabled.
export function getSecurityConfig() {
  return {
	protocolVersion: process.env.AUTHBRIDGE_PROTOCOL_VERSION || DEFAULT_PROTOCOL_VERSION,
	secureProtocolVersion: process.env.AUTHBRIDGE_SECURE_PROTOCOL_VERSION || DEFAULT_SECURE_PROTOCOL_VERSION,
	// This API key is a shared secret between AdhocReport and the customer authorization server.
	requireRequestApiKey: parseBoolean(process.env.AUTHBRIDGE_REQUIRE_REQUEST_API_KEY, true),
	requestApiKeyHeaderName: (process.env.AUTHBRIDGE_REQUEST_API_KEY_HEADER_NAME || 'x-bridge-api-key').toLowerCase(),
	requestApiKey: process.env.AUTHBRIDGE_REQUEST_API_KEY || '',
	protocolHeaderName: (process.env.AUTHBRIDGE_PROTOCOL_HEADER_NAME || 'x-authbridge-protocol').toLowerCase(),
	correlationIdHeaderName: (process.env.AUTHBRIDGE_CORRELATION_HEADER_NAME || 'x-correlation-id').toLowerCase(),
	maxClockSkewSeconds: parseNumber(process.env.AUTHBRIDGE_MAX_CLOCK_SKEW_SECONDS, DEFAULT_CLOCK_SKEW_SECONDS),
	replayTtlSeconds: parseNumber(process.env.AUTHBRIDGE_REPLAY_TTL_SECONDS, DEFAULT_REPLAY_TTL_SECONDS),
	keyAgreementCurve: process.env.AUTHBRIDGE_KEY_AGREEMENT_CURVE || 'X25519',
	kdfAlgorithm: process.env.AUTHBRIDGE_KDF_ALGORITHM || 'HKDF-SHA256',
	contentEncryption: process.env.AUTHBRIDGE_CONTENT_ENCRYPTION || 'A256GCM',
	signatureAlgorithm: process.env.AUTHBRIDGE_SIGNATURE_ALGORITHM || 'Ed25519',
	kdfInfo: process.env.AUTHBRIDGE_KDF_INFO || 'authbridge-validate-secure:v2',
	requiredEnvelopeFields: [
	  'protocolVersion',
	  'keyId',
	  'signatureKeyId',
	  'clientId',
	  'requestId',
	  'timestampUtc',
	  'clientEphemeralPublicKey',
	  'nonce',
	  'aad',
	  'ciphertext',
	  'tag',
	  'signature'
	]
  };
}
