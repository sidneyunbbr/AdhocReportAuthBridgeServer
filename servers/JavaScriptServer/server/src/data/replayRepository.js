/**
 * Module purpose:
 * Encapsulates replay-protection data operations used by secure request validation.
 * It provides a focused API for cleanup, existence checks, and registration of request fingerprints.
 */
import { cleanupExpiredReplays, findReplay, saveReplay } from './sqlite.js';

// Removes expired replay rows before evaluating new secure requests.
export function purgeExpiredReplayEntries(nowUtcIso) {
  return cleanupExpiredReplays(nowUtcIso);
}

// Checks whether a clientId/requestId pair has been processed already.
export function existsReplay(clientId, requestId) {
  return findReplay(clientId, requestId) !== null;
}

// Persists the request fingerprint used by replay protection.
export function registerReplay(clientId, requestId, requestTimestampUtc, nowUtcIso, expiresAtUtcIso) {
  return saveReplay({
	clientId,
	requestId,
	requestTimestampUtc,
	createdAtUtc: nowUtcIso,
	expiresAtUtc: expiresAtUtcIso
  });
}
