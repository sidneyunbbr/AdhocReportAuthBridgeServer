/**
 * Module purpose:
 * Encapsulates decrypted payload validation and authentication business decision logic.
 * This keeps secureValidationService focused on protocol/signature/crypto orchestration,
 * while this module is the primary customization point for customer identity rules.
   * IMPORTANT: AuthBridge transport decryption is the shared/common step across integrations.
 * After decrypting payload.password, customer implementations must apply their own
 * local password hashing/verification method against their real user store.
 * This reference implementation compares plaintext password for demo only.
 */
import { findExternalAuthUserByExternalId, findExternalAuthUserByUsername } from '../data/sqlite.js';

// Normalizes optional payload values so business checks can use null/trimmed strings consistently.
function normalizeNullableString(value) {
  if (value === undefined || value === null) {
	return null;
  }

  const normalized = String(value).trim();
  return normalized.length === 0 ? null : normalized;
}

// Contract payload for authentication failures, later encrypted by secureEnvelopeCrypto.
function buildFailurePayload(message, errorCode) {
  return {
	isValid: false,
	externalUserId: null,
	email: null,
	fullName: null,
	message,
	errorCode
  };
}

// Standardized evaluation shape for invalid decrypted payload cases.
function buildInvalidEvaluation(errorKey, details) {
  return {
	ok: false,
	errorKey,
	details,
	businessPayload: null
  };
}

// Standardized evaluation shape for valid payload cases (success or auth failure payload).
function buildValidEvaluation(businessPayload) {
  return {
	ok: true,
	errorKey: null,
	details: null,
	businessPayload
  };
}

// Contract payload for successful authentication, later encrypted by secureEnvelopeCrypto.
function buildSuccessPayload(user) {
  return {
	isValid: true,
	externalUserId: user.externalUserId,
	email: user.email,
	fullName: user.fullName,
	message: null,
	errorCode: null
  };
}

// User lookup strategy mirrors AdhocReport contract: externalUserId first, then username fallback.
function findAuthUser(username, externalUserId) {
  if (externalUserId) {
	return findExternalAuthUserByExternalId(externalUserId);
  }

  if (username) {
	return findExternalAuthUserByUsername(username);
  }

  return null;
}

// Shared validator error shape used when decrypted business payload is malformed.
function buildValidationInputError(message) {
	return buildInvalidEvaluation('secureEnvelopeInvalid', message);
}

// Validates decrypted request body content expected by external_auth_users lookup.
function validateDecryptedPayload(payload) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
	return buildValidationInputError('Decrypted payload must be a JSON object.');
  }

  const username = normalizeNullableString(payload.username);
  const externalUserId = normalizeNullableString(payload.externalUserId);
  const password = normalizeNullableString(payload.password);

  if (!username && !externalUserId) {
	return buildValidationInputError("At least one of 'username' or 'externalUserId' must be provided.");
  }

  if (!password) {
	return buildValidationInputError("Field 'password' is required in decrypted payload.");
  }

  return {
	ok: true,
	errorKey: null,
	details: null,
	username,
	externalUserId,
	password,
	businessPayload: null
  };
}

// Main business-decision entrypoint used by secureValidationService after decryption.
export function evaluateAuthenticationPayload(decryptedPayload) {
  const payloadValidation = validateDecryptedPayload(decryptedPayload);
  if (!payloadValidation.ok) {
	return payloadValidation;
  }

  const user = findAuthUser(payloadValidation.username, payloadValidation.externalUserId);

  if (!user) {
	return buildValidEvaluation(buildFailurePayload('Authentication failed.', 'user-not-found'));
  }

  if (!user.isEnabled) {
	return buildValidEvaluation(buildFailurePayload('Authentication failed.', 'user-disabled'));
  }

  if (user.password !== payloadValidation.password) {
	// Step 1 (shared): payload.password was already decrypted by AuthBridge secure flow.
	// Step 2 (customer-specific): replace this demo comparison with local hash verification
	// against the customer's own credential store.
	return buildValidEvaluation(buildFailurePayload('Authentication failed.', 'invalid-credentials'));
  }

	return buildValidEvaluation(buildSuccessPayload(user));
}
