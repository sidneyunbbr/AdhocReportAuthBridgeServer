/**
 * Module purpose:
 * Executes pre-cryptographic validation for secure AuthBridge requests.
 * It verifies headers, envelope structure, timestamp freshness, and replay constraints.
 */
import { getSecurityConfig } from '../config/securityConfig.js';
import { existsReplay, purgeExpiredReplayEntries, registerReplay } from '../data/replayRepository.js';

// Reads HTTP header values in a case-insensitive way.
function getHeaderValue(req, headerName) {
  return req.headers[headerName] ?? req.headers[headerName.toLowerCase()] ?? null;
}

// Minimal ISO timestamp validation used for freshness checks.
function isIsoDate(value) {
  if (typeof value !== 'string' || value.trim().length === 0) {
	return false;
  }

  const parsed = Date.parse(value);
  return Number.isFinite(parsed);
}

function addSeconds(date, seconds) {
  return new Date(date.getTime() + seconds * 1000);
}

// Standard result model shared between validation and route handlers.
function buildResult(ok, errorKey, details, context) {
  return {
	ok,
	errorKey: errorKey || null,
	details: details || null,
	context: context || {}
  };
}

// Produces standardized failure result preserving correlation id in one place.
function fail(correlationId, errorKey, details) {
  return buildResult(false, errorKey, details, {
	correlationId
  });
}

// Produces standardized success result for downstream secure processing.
function success(correlationId, envelope, protocolVersion) {
  return buildResult(true, null, null, {
	correlationId,
	envelope,
	protocolVersion
  });
}

// Validates transport + envelope + freshness + replay preconditions for secure requests.
export function validateSecureRequest(req) {
  const config = getSecurityConfig();

  const correlationIdHeader = getHeaderValue(req, config.correlationIdHeaderName);
  const protocolHeader = getHeaderValue(req, config.protocolHeaderName);
  const apiKeyHeader = getHeaderValue(req, config.requestApiKeyHeaderName);

	// API key check blocks unauthorized callers before any expensive crypto/database processing.
  if (config.requireRequestApiKey) {
	if (!apiKeyHeader || apiKeyHeader !== config.requestApiKey) {
	  return fail(correlationIdHeader, 'bridgeUnauthorizedCaller', 'Missing or invalid API key header.');
	}
  }

	if (!protocolHeader || protocolHeader !== config.secureProtocolVersion) {
	return fail(correlationIdHeader, 'unsupportedProtocol', 'Header protocol version is missing or unsupported.');
  }

  const envelope = req.body;
  if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope)) {
	return fail(correlationIdHeader, 'secureEnvelopeInvalid', 'Request body must be a JSON object.');
  }

	// Required field list comes from securityConfig so contract changes stay centralized.
  for (const fieldName of config.requiredEnvelopeFields) {
	const value = envelope[fieldName];
	if (typeof value !== 'string' || value.trim().length === 0) {
	  return fail(correlationIdHeader, 'secureEnvelopeInvalid', `Envelope field '${fieldName}' is required.`);
	}
  }

	if (envelope.protocolVersion !== config.secureProtocolVersion) {
	return fail(correlationIdHeader, 'unsupportedProtocol', 'Envelope protocolVersion is unsupported.');
  }

  if (!isIsoDate(envelope.timestampUtc)) {
	return fail(correlationIdHeader, 'secureEnvelopeInvalid', "Envelope field 'timestampUtc' must be a valid ISO timestamp.");
  }

  const nowUtc = new Date();
  const requestUtc = new Date(envelope.timestampUtc);
  const maxSkewMs = config.maxClockSkewSeconds * 1000;
  const skewMs = Math.abs(nowUtc.getTime() - requestUtc.getTime());

  if (skewMs > maxSkewMs) {
	return fail(correlationIdHeader, 'requestExpired', 'Request timestamp is outside allowed clock skew window.');
  }

	// Best-effort cleanup keeps replay table bounded without an external scheduler.
  purgeExpiredReplayEntries(nowUtc.toISOString());

  const clientId = envelope.clientId;
  const requestId = envelope.requestId;

	// Replay uniqueness is enforced by clientId + requestId pair (durable anti-replay requirement).
  if (existsReplay(clientId, requestId)) {
	return fail(correlationIdHeader, 'requestReplayed', 'Duplicate request for clientId/requestId.');
  }

  const expiresAtUtc = addSeconds(nowUtc, config.replayTtlSeconds);
	// Register replay marker before crypto/business processing to reduce race windows.
  registerReplay(clientId, requestId, envelope.timestampUtc, nowUtc.toISOString(), expiresAtUtc.toISOString());

	return success(correlationIdHeader, envelope, config.secureProtocolVersion);
}
