/**
 * Module purpose:
 * Implements deterministic signature input and Ed25519 sign/verify operations
 * for secure request and response envelopes.
 */
import { sign, verify } from 'node:crypto';
import { fromBase64Url, toBase64Url } from './base64url.js';

// Produces deterministic binary input from ordered text fields (contract canonical form).
function joinWithNewLine(values) {
  return Buffer.from(values.join('\n'), 'utf8');
}

// Canonical string-to-sign for inbound secure request (must match customer implementation exactly).
export function buildRequestSigningInput(envelope) {
  return joinWithNewLine([
	envelope.protocolVersion,
	envelope.keyId,
	envelope.signatureKeyId,
	envelope.clientId,
	envelope.requestId,
	envelope.timestampUtc,
	envelope.clientEphemeralPublicKey,
	envelope.nonce,
	envelope.aad,
	envelope.ciphertext,
	envelope.tag
  ]);
}

// Canonical string-to-sign for secure response (used by server and example client verification).
export function buildResponseSigningInput(envelope) {
  return joinWithNewLine([
	envelope.protocolVersion,
	envelope.responseId,
	envelope.requestId,
	envelope.timestampUtc,
	envelope.nonce,
	envelope.aad,
	envelope.ciphertext,
	envelope.tag,
	envelope.signatureKeyId
  ]);
}

// Used by secureValidationService before decrypting payload, preventing unauthenticated processing.
export function verifyRequestSignature(envelope, publicKey) {
  const signatureBytes = fromBase64Url(envelope.signature);
  const signingInput = buildRequestSigningInput(envelope);

	return verify(null, signingInput, publicKey, signatureBytes);
}

// Used by secureValidationService to sign response envelope returned to AdhocReport caller.
export function signResponseEnvelope(envelope, privateKey) {
  const signingInput = buildResponseSigningInput(envelope);
	const signature = sign(null, signingInput, privateKey);
  return toBase64Url(signature);
}
