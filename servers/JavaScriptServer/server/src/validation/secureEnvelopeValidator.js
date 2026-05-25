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

// Validates transport + envelope + freshness + replay preconditions for secure requests.
export function validateSecureRequest(req) {
  const config = getSecurityConfig();

  const correlationIdHeader = getHeaderValue(req, config.correlationIdHeaderName);
  const protocolHeader = getHeaderValue(req, config.protocolHeaderName);
  const apiKeyHeader = getHeaderValue(req, config.requestApiKeyHeaderName);

  if (config.requireRequestApiKey) {
	if (!apiKeyHeader || apiKeyHeader !== config.requestApiKey) {
	  return buildResult(false, 'bridgeUnauthorizedCaller', 'Missing or invalid API key header.', {
		correlationId: correlationIdHeader
	  });
	}
  }

	if (!protocolHeader || protocolHeader !== config.secureProtocolVersion) {
	return buildResult(false, 'unsupportedProtocol', 'Header protocol version is missing or unsupported.', {
	  correlationId: correlationIdHeader
	});
  }

  const envelope = req.body;
  if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope)) {
	return buildResult(false, 'secureEnvelopeInvalid', 'Request body must be a JSON object.', {
	  correlationId: correlationIdHeader
	});
  }

  for (const fieldName of config.requiredEnvelopeFields) {
	const value = envelope[fieldName];
	if (typeof value !== 'string' || value.trim().length === 0) {
	  return buildResult(false, 'secureEnvelopeInvalid', `Envelope field '${fieldName}' is required.`, {
		correlationId: correlationIdHeader
	  });
	}
  }

	if (envelope.protocolVersion !== config.secureProtocolVersion) {
	return buildResult(false, 'unsupportedProtocol', 'Envelope protocolVersion is unsupported.', {
	  correlationId: correlationIdHeader
	});
  }

  if (!isIsoDate(envelope.timestampUtc)) {
	return buildResult(false, 'secureEnvelopeInvalid', "Envelope field 'timestampUtc' must be a valid ISO timestamp.", {
	  correlationId: correlationIdHeader
	});
  }

  const nowUtc = new Date();
  const requestUtc = new Date(envelope.timestampUtc);
  const maxSkewMs = config.maxClockSkewSeconds * 1000;
  const skewMs = Math.abs(nowUtc.getTime() - requestUtc.getTime());

  if (skewMs > maxSkewMs) {
	return buildResult(false, 'requestExpired', 'Request timestamp is outside allowed clock skew window.', {
	  correlationId: correlationIdHeader
	});
  }

  purgeExpiredReplayEntries(nowUtc.toISOString());

  const clientId = envelope.clientId;
  const requestId = envelope.requestId;

  if (existsReplay(clientId, requestId)) {
	return buildResult(false, 'requestReplayed', 'Duplicate request for clientId/requestId.', {
	  correlationId: correlationIdHeader
	});
  }

  const expiresAtUtc = addSeconds(nowUtc, config.replayTtlSeconds);
  registerReplay(clientId, requestId, envelope.timestampUtc, nowUtc.toISOString(), expiresAtUtc.toISOString());

  return buildResult(true, null, null, {
	correlationId: correlationIdHeader,
	envelope,
	protocolVersion: config.secureProtocolVersion
  });
}
