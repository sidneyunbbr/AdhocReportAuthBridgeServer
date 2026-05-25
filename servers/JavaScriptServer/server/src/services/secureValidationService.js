/**
 * Module purpose:
 * Executes the secure validation business pipeline after transport prechecks pass.
 * It verifies request signature, decrypts payload, validates credentials, and returns
 * an encrypted + signed response envelope aligned with the AuthBridge contract.
 */
import { randomUUID } from 'node:crypto';
import { findExternalAuthUserByExternalId, findExternalAuthUserByUsername } from '../data/sqlite.js';
import { deriveRequestKey, decryptRequestPayload, encryptResponsePayload } from '../crypto/secureEnvelopeCrypto.js';
import { getClientPublicSigningKeyById, getKeyIdentifiers, getServerSignatureKeyPair } from '../crypto/keyStore.js';
import { signResponseEnvelope, verifyRequestSignature } from '../crypto/signature.js';
import { getSecurityConfig } from '../config/securityConfig.js';

function normalizeNullableString(value) {
  if (value === undefined || value === null) {
	return null;
  }

  const normalized = String(value).trim();
  return normalized.length === 0 ? null : normalized;
}

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

function findAuthUser(username, externalUserId) {
  if (externalUserId) {
	return findExternalAuthUserByExternalId(externalUserId);
  }

  if (username) {
	return findExternalAuthUserByUsername(username);
  }

  return null;
}

function buildResponseEnvelope(envelope, encryptedPayload) {
  const config = getSecurityConfig();
  const keyIds = getKeyIdentifiers();

  return {
	protocolVersion: config.secureProtocolVersion,
	responseId: randomUUID(),
	requestId: envelope.requestId,
	timestampUtc: new Date().toISOString(),
	nonce: encryptedPayload.nonce,
	aad: encryptedPayload.aad,
	ciphertext: encryptedPayload.ciphertext,
	tag: encryptedPayload.tag,
	signatureKeyId: keyIds.serverSignatureKeyId,
	signature: null
  };
}

function buildValidationInputError(message) {
  return {
	ok: false,
	errorKey: 'secureEnvelopeInvalid',
	details: message,
	envelope: null
  };
}

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
	username,
	externalUserId,
	password,
	correlationId: normalizeNullableString(payload.correlationId)
  };
}

export function processSecureValidation(envelope) {
  const config = getSecurityConfig();
  const keyIds = getKeyIdentifiers();

  if (envelope.protocolVersion !== config.secureProtocolVersion) {
	return {
	  ok: false,
	  errorKey: 'unsupportedProtocol',
	  details: 'Secure protocol version in envelope is not supported.'
	};
  }

  if (envelope.keyId !== keyIds.encryptionKeyId) {
	return {
	  ok: false,
	  errorKey: 'unsupportedKeyOrProtocol',
	  details: 'Encryption keyId is not recognized by this server.'
	};
  }

  const clientPublicSigningKey = getClientPublicSigningKeyById(envelope.signatureKeyId);
  if (!clientPublicSigningKey) {
	return {
	  ok: false,
	  errorKey: 'unsupportedKeyOrProtocol',
	  details: 'Client signature keyId is not recognized by this server.'
	};
  }

  const signatureOk = verifyRequestSignature(envelope, clientPublicSigningKey);
  if (!signatureOk) {
	return {
	  ok: false,
	  errorKey: 'signatureInvalid',
	  details: 'Envelope signature verification failed.'
	};
  }

  let derivedKey;
  let decryptedPayload;

  try {
	derivedKey = deriveRequestKey(envelope);
	decryptedPayload = decryptRequestPayload(envelope, derivedKey);
  } catch (error) {
	return {
	  ok: false,
	  errorKey: 'payloadDecryptFailed',
	  details: `Unable to decrypt secure payload. ${error?.message || ''}`.trim()
	};
  }

  const payloadValidation = validateDecryptedPayload(decryptedPayload);
  if (!payloadValidation.ok) {
	return {
	  ok: false,
	  errorKey: payloadValidation.errorKey,
	  details: payloadValidation.details
	};
  }

  const user = findAuthUser(payloadValidation.username, payloadValidation.externalUserId);

  let businessPayload;
  if (!user) {
	businessPayload = buildFailurePayload('Authentication failed.', 'user-not-found');
  } else if (!user.isEnabled) {
	businessPayload = buildFailurePayload('Authentication failed.', 'user-disabled');
  } else if (user.password !== payloadValidation.password) {
	businessPayload = buildFailurePayload('Authentication failed.', 'invalid-credentials');
  } else {
	businessPayload = buildSuccessPayload(user);
  }

  try {
	const responseEnvelope = buildResponseEnvelope(envelope, {
	  nonce: null,
	  aad: null,
	  ciphertext: null,
	  tag: null
	});

	const responseAadObject = {
	  protocolVersion: responseEnvelope.protocolVersion,
	  requestId: responseEnvelope.requestId,
	  responseId: responseEnvelope.responseId,
	  timestampUtc: responseEnvelope.timestampUtc,
	  signatureKeyId: responseEnvelope.signatureKeyId
	};

	const encryptedResponse = encryptResponsePayload(businessPayload, derivedKey, responseAadObject);

	responseEnvelope.nonce = encryptedResponse.nonce;
	responseEnvelope.aad = encryptedResponse.aad;
	responseEnvelope.ciphertext = encryptedResponse.ciphertext;
	responseEnvelope.tag = encryptedResponse.tag;
	responseEnvelope.signature = signResponseEnvelope(responseEnvelope, getServerSignatureKeyPair().privateKey);

	return {
	  ok: true,
	  responseEnvelope,
	  businessPayload
	};
  } catch (error) {
	return {
	  ok: false,
	  errorKey: 'secureProcessingFailure',
	  details: `Unable to encrypt/sign secure response. ${error?.message || ''}`.trim()
	};
  }
}
