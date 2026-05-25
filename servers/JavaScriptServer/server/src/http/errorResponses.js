/**
 * Module purpose:
 * Provides standardized transport error mapping for AuthBridge secure endpoint responses.
 * It ensures callers receive deterministic status codes and error payload structure.
 */
const ERROR_MAP = {
  malformedEnvelope: {
	status: 400,
	errorCode: 'malformed-envelope',
	message: 'Malformed secure envelope.'
  },
  unauthorizedCaller: {
	status: 401,
	errorCode: 'unauthorized-caller',
	message: 'Unauthorized caller.'
  },
  expiredRequest: {
	status: 408,
	errorCode: 'expired-request-window',
	message: 'Request timestamp is outside the accepted window.'
  },
  replayDetected: {
	status: 409,
	errorCode: 'replay-detected',
	message: 'Replay detected for clientId and requestId.'
  },
  unsupportedProtocol: {
	status: 422,
	errorCode: 'unsupported-protocol',
	message: 'Unsupported protocol version.'
  },
	unsupportedKeyOrProtocol: {
	status: 422,
	errorCode: 'unsupported-key-or-protocol',
	message: 'Unsupported key id or protocol.'
  },
  secureEnvelopeInvalid: {
	status: 400,
	errorCode: 'secure-envelope-invalid',
	message: 'Secure request envelope is invalid.'
  },
  requestExpired: {
	status: 408,
	errorCode: 'request-expired',
	message: 'Request timestamp is outside allowed skew window.'
  },
  requestReplayed: {
	status: 409,
	errorCode: 'request-replayed',
	message: 'Request replay detected.'
  },
  bridgeUnauthorizedCaller: {
	status: 401,
	errorCode: 'bridge-unauthorized-caller',
	message: 'Caller is not authorized to use this endpoint.'
  },
  secureProcessingFailure: {
	status: 500,
	errorCode: 'secure-processing-failure',
	message: 'Secure validation processing failed.'
  },
  signatureInvalid: {
	status: 400,
	errorCode: 'signature-invalid',
	message: 'Request signature validation failed.'
  },
  payloadDecryptFailed: {
	status: 400,
	errorCode: 'payload-decrypt-failed',
	message: 'Unable to decrypt secure request payload.'
  },
  secureFlowPending: {
	status: 501,
	errorCode: 'secure-flow-pending',
	message: 'Secure validation cryptographic pipeline not implemented yet.'
  }
};

// Returns normalized transport error definition by logical key.
export function getErrorDefinition(key) {
  return ERROR_MAP[key] || ERROR_MAP.malformedEnvelope;
}

// Sends deterministic HTTP error payloads aligned with contract categories.
export function sendError(res, key, correlationId, details) {
  const error = getErrorDefinition(key);

  return res.status(error.status).json({
	isValid: false,
	errorCode: error.errorCode,
	message: error.message,
	correlationId: correlationId || null,
	details: details || null
  });
}
