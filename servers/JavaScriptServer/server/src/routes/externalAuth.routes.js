/**
 * Module purpose:
 * Exposes the external authentication contract endpoints used by client integrations.
 * This file concentrates HTTP route behavior (health, keys, and secure validation flow).
 */
import { Router } from 'express';
import { getKeyDiscoveryPayload } from '../crypto/keyStore.js';
import { sendError } from '../http/errorResponses.js';
import { processSecureValidation } from '../services/secureValidationService.js';
import { validateSecureRequest } from '../validation/secureEnvelopeValidator.js';

const router = Router();

// Read-only endpoint used by clients/monitoring to verify service availability.
router.get('/health', (req, res) => {
  res.status(200).json({
	status: 'ok',
	service: 'AdhocReportAuthBridgeServer.JavaScript',
	timestampUtc: new Date().toISOString()
  });
});

// Publishes active key metadata consumed by clients before building signed/encrypted requests.
router.get('/keys', (req, res) => {
  return res.status(200).json(getKeyDiscoveryPayload());
});

// Route chain: validateSecureRequest (transport/replay) -> processSecureValidation (crypto+business).
router.post('/validate-secure', (req, res) => {
  const validation = validateSecureRequest(req);

  if (!validation.ok) {
	return sendError(
	  res,
	  validation.errorKey,
	  validation.context?.correlationId,
	  validation.details
	);
  }

	const secureResult = processSecureValidation(validation.context.envelope);

  if (!secureResult.ok) {
	return sendError(
	  res,
	  secureResult.errorKey,
	  validation.context?.correlationId,
	  secureResult.details
	);
  }

  return res.status(200).json(secureResult.responseEnvelope);
});

export default router;
