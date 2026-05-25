/**
 * Module purpose:
 * Executes the secure validation business pipeline after transport prechecks pass.
 * It verifies request signature, decrypts payload, validates credentials, and returns
 * an encrypted + signed response envelope aligned with the AuthBridge contract.
 */
import { randomUUID } from 'node:crypto';
import { buildResponseAad, deriveRequestKey, decryptRequestPayload, encryptResponsePayload } from '../crypto/secureEnvelopeCrypto.js';
import {
  getActiveServerSignatureKeyRecord,
  getClientPublicSigningKeyById,
  getServerSignaturePrivateKeyById,
  isSupportedEncryptionKeyId,
  isSupportedClientSignatureKeyId
} from '../crypto/keyStore.js';
import { signResponseEnvelope, verifyRequestSignature } from '../crypto/signature.js';
import { getSecurityConfig } from '../config/securityConfig.js';
import { evaluateAuthenticationPayload } from './authDecisionService.js';

// Standardized error result shape for route-level deterministic mapping.
function buildErrorResult(errorKey, details) {
  return {
    ok: false,
    errorKey,
    details
  };
}

// Standardized success result shape for secure validation responses.
function buildSuccessResult(responseEnvelope, businessPayload) {
  return {
    ok: true,
    responseEnvelope,
    businessPayload
  };
}

// Placeholder payload used to initialize response envelope before encrypted values are computed.
function createEmptyEncryptedPayload() {
  return {
    nonce: null,
    aad: null,
    ciphertext: null,
    tag: null
  };
}

// Creates response envelope shell before encryption/signature are attached.
function buildResponseEnvelope(envelope, encryptedPayload, signatureKeyId) {
  const config = getSecurityConfig();

  return {
    protocolVersion: config.secureProtocolVersion,
    responseId: randomUUID(),
    requestId: envelope.requestId,
    timestampUtc: new Date().toISOString(),
    nonce: encryptedPayload.nonce,
    aad: encryptedPayload.aad,
    ciphertext: encryptedPayload.ciphertext,
    tag: encryptedPayload.tag,
    signatureKeyId,
    signature: null
  };
}

// Main secure pipeline called by externalAuth.routes after transport/replay prechecks succeed.
export function processSecureValidation(envelope) {
  const config = getSecurityConfig();

  if (envelope.protocolVersion !== config.secureProtocolVersion) {
    return buildErrorResult('unsupportedProtocol', 'Secure protocol version in envelope is not supported.');
  }

  if (!isSupportedEncryptionKeyId(envelope.keyId)) {
    return buildErrorResult('unsupportedKeyOrProtocol', 'Encryption keyId is not recognized by this server.');
  }

  if (!isSupportedClientSignatureKeyId(envelope.signatureKeyId)) {
    return buildErrorResult('unsupportedKeyOrProtocol', 'Client signature keyId is not recognized by this server.');
  }

  const clientPublicSigningKey = getClientPublicSigningKeyById(envelope.signatureKeyId);
  // Signature is verified before decryption to avoid processing unauthenticated ciphertext.
  const signatureOk = verifyRequestSignature(envelope, clientPublicSigningKey);
  if (!signatureOk) {
    return buildErrorResult('signatureInvalid', 'Envelope signature verification failed.');
  }

  let derivedKey;
  let decryptedPayload;

  try {
    // Key derivation and AES-GCM decryption are delegated to secureEnvelopeCrypto helpers.
    derivedKey = deriveRequestKey(envelope);
    decryptedPayload = decryptRequestPayload(envelope, derivedKey);
  } catch (error) {
    return buildErrorResult('payloadDecryptFailed', `Unable to decrypt secure payload. ${error?.message || ''}`.trim());
  }

  // Business validation and auth decision are delegated to authDecisionService.
  const authenticationEvaluation = evaluateAuthenticationPayload(decryptedPayload);
  if (!authenticationEvaluation.ok) {
    return buildErrorResult(authenticationEvaluation.errorKey, authenticationEvaluation.details);
  }

  const businessPayload = authenticationEvaluation.businessPayload;

  try {
    const activeServerSignatureRecord = getActiveServerSignatureKeyRecord();
    if (!activeServerSignatureRecord) {
      return buildErrorResult('secureProcessingFailure', 'No active server signing key is available.');
    }

    const responseEnvelope = buildResponseEnvelope(
      envelope,
      createEmptyEncryptedPayload(),
      activeServerSignatureRecord.keyId
    );

    const responseAadObject = buildResponseAad(responseEnvelope);

    // Encrypt response payload with request-derived key, keeping response envelope metadata in AAD.
    const encryptedResponse = encryptResponsePayload(businessPayload, derivedKey, responseAadObject);

    responseEnvelope.nonce = encryptedResponse.nonce;
    responseEnvelope.aad = encryptedResponse.aad;
    responseEnvelope.ciphertext = encryptedResponse.ciphertext;
    responseEnvelope.tag = encryptedResponse.tag;

    const serverSignaturePrivateKey = getServerSignaturePrivateKeyById(responseEnvelope.signatureKeyId);
    // Signature over encrypted envelope gives integrity for response metadata + ciphertext.
    responseEnvelope.signature = signResponseEnvelope(responseEnvelope, serverSignaturePrivateKey);

    return buildSuccessResult(responseEnvelope, businessPayload);
  } catch (error) {
    return buildErrorResult('secureProcessingFailure', `Unable to encrypt/sign secure response. ${error?.message || ''}`.trim());
  }
}
