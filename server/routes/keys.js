import { Router } from 'express';
import config from '../config.js';
import { getActiveKey } from '../db/index.js';

export function createKeysRouter(appConfig = config) {
  const router = Router();

  router.get('/keys', async (_req, res, next) => {
    try {
      const key = getActiveKey();

      if (!key) {
        throw new Error('No active server key found.');
      }

      res.json({
        keyId: key.key_id,
        algorithm: key.algorithm,
        validFrom: key.valid_from,
        validUntil: key.valid_until,
        serverTime: new Date().toISOString(),
        protocolVersion: appConfig.PROTOCOL_VERSION,
        publicKey: key.public_key_pem
      });
    } catch (error) {
      next(error);
    }
  });

  return router;
}
