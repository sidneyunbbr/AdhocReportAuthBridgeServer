import { randomUUID } from 'node:crypto';
import { Router } from 'express';
import config from '../config.js';
import logger from '../logger.js';
import { sendError } from '../http.js';
import {
  checkReplay,
  cleanExpiredReplays,
  findUser,
  getActiveKey,
  insertAuditLog,
  insertReplay
} from '../db/index.js';
import {
  createHmacSignature,
  decryptPayload,
  deriveAesKey,
  deriveSharedSecret,
  encryptPayload,
  verifyHmacSignature,
  verifyPassword
} from '../crypto/index.js';

const REQUIRED_FIELDS = [
  'keyId',
  'clientId',
  'requestId',
  'timestamp',
  'clientPublicKey',
  'signature',
  'encryptedPayload',
  'iv',
  'authTag'
];
const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX_REQUESTS = 60;
const rateLimitState = new Map();

function consumeRateLimit(clientId, now = Date.now()) {
  const current = rateLimitState.get(clientId);

  if (!current || current.expiresAt <= now) {
    rateLimitState.set(clientId, { count: 1, expiresAt: now + RATE_LIMIT_WINDOW_MS });
    return true;
  }

  if (current.count >= RATE_LIMIT_MAX_REQUESTS) {
    return false;
  }

  current.count += 1;
  return true;
}

export function buildCanonicalString(envelope) {
  return [
    envelope.keyId,
    envelope.clientId,
    envelope.requestId,
    envelope.timestamp,
    envelope.clientPublicKey,
    envelope.encryptedPayload
  ].join('|');
}

export function validateEnvelopeFields(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return { valid: false, message: 'Envelope must be a JSON object.' };
  }

  for (const field of REQUIRED_FIELDS) {
    if (body[field] === undefined || body[field] === null || body[field] === '') {
      return { valid: false, message: `Missing required field: ${field}` };
    }
  }

  if (!Number.isFinite(Number(body.timestamp))) {
    return { valid: false, message: 'timestamp must be a valid number.' };
  }

  return { valid: true };
}

export function isTimestampValid(timestamp, toleranceSeconds, now = Date.now()) {
  return Math.abs(Number(timestamp) - now) <= toleranceSeconds * 1000;
}

function auditAndSendError(req, res, status, code, message, clientId = null) {
  insertAuditLog({
    requestRef: req.requestRef,
    clientId,
    eventType: 'validate_secure',
    status: code,
    detail: { httpStatus: status }
  });
  logger.warn(message, { requestRef: req.requestRef, code, clientId });
  return sendError(res, req, status, code, message);
}

export function createValidateSecureRouter(appConfig = config) {
  const router = Router();

  router.post('/validate-secure', async (req, res, next) => {
    try {
      const validation = validateEnvelopeFields(req.body);

      if (!validation.valid) {
        return auditAndSendError(
          req,
          res,
          400,
          'invalid_envelope',
          validation.message,
          req.body?.clientId ?? null
        );
      }

      const envelope = req.body;
      const clientId = req.clientInfo?.clientId ?? envelope.clientId;

      if (envelope.clientId !== clientId) {
        return auditAndSendError(
          req,
          res,
          401,
          'unauthorized',
          'Envelope clientId does not match the authenticated API client.',
          clientId
        );
      }

      if (!consumeRateLimit(clientId)) {
        return auditAndSendError(
          req,
          res,
          429,
          'rate_limited',
          'Too many authentication attempts. Please retry shortly.',
          clientId
        );
      }

      if (!isTimestampValid(envelope.timestamp, appConfig.TIMESTAMP_TOLERANCE_SECONDS)) {
        return auditAndSendError(
          req,
          res,
          408,
          'timestamp_expired',
          'Envelope timestamp is outside the allowed tolerance window.',
          clientId
        );
      }

      cleanExpiredReplays();
      if (checkReplay(clientId, envelope.requestId)) {
        return auditAndSendError(
          req,
          res,
          409,
          'replay_detected',
          'Replay detected for the supplied requestId.',
          clientId
        );
      }

      const activeKey = getActiveKey();

      if (!activeKey || activeKey.key_id !== envelope.keyId) {
        return auditAndSendError(
          req,
          res,
          400,
          'invalid_envelope',
          'Envelope keyId does not match the active server key.',
          clientId
        );
      }

      const canonical = buildCanonicalString(envelope);
      const expectedSignature = createHmacSignature(req.apiKeyRaw, canonical);

      if (!verifyHmacSignature(req.apiKeyRaw, canonical, envelope.signature)) {
        logger.debug('Signature mismatch detected.', {
          requestRef: req.requestRef,
          clientId,
          expectedLength: expectedSignature.length
        });
        return auditAndSendError(
          req,
          res,
          422,
          'signature_invalid',
          'Envelope signature verification failed.',
          clientId
        );
      }

      let aesKey;
      let credentials;

      try {
        const sharedSecret = deriveSharedSecret(activeKey.private_key_pem, envelope.clientPublicKey);
        aesKey = deriveAesKey(sharedSecret, 'authbridge-aes-key', envelope.requestId);
        const decryptedPayload = decryptPayload(
          envelope.encryptedPayload,
          aesKey,
          envelope.iv,
          envelope.authTag
        );
        credentials = JSON.parse(decryptedPayload.toString('utf8'));
      } catch {
        return auditAndSendError(
          req,
          res,
          422,
          'decryption_failed',
          'Unable to decrypt the envelope payload.',
          clientId
        );
      }

      if (
        !credentials ||
        typeof credentials.username !== 'string' ||
        typeof credentials.password !== 'string'
      ) {
        return auditAndSendError(
          req,
          res,
          400,
          'invalid_envelope',
          'Decrypted payload must contain username and password.',
          clientId
        );
      }

      const user = findUser(credentials.username);

      if (!user || !verifyPassword(credentials.password, user.password_hash)) {
        return auditAndSendError(
          req,
          res,
          401,
          'authentication_failed',
          'Invalid username or password.',
          clientId
        );
      }

      insertReplay(clientId, envelope.requestId, appConfig.REPLAY_TTL_SECONDS);

      const result = {
        authenticated: true,
        username: user.username,
        role: user.role,
        sessionRef: randomUUID()
      };
      const encryptedResult = encryptPayload(JSON.stringify(result), aesKey);

      insertAuditLog({
        requestRef: req.requestRef,
        clientId,
        eventType: 'validate_secure',
        status: 'success',
        detail: { username: user.username, role: user.role }
      });

      res.json({
        status: 'success',
        encryptedResult: encryptedResult.ciphertext,
        iv: encryptedResult.iv,
        authTag: encryptedResult.authTag
      });
    } catch (error) {
      next(error);
    }
  });

  return router;
}
