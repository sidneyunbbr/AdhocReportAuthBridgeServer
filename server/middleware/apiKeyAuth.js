import config from '../config.js';
import { getApiClientByHash } from '../db/index.js';
import { sendError } from '../http.js';
import { hashApiKey } from '../crypto/index.js';

export function apiKeyAuthMiddleware(appConfig = config) {
  return (req, res, next) => {
    const apiKey = req.get(appConfig.API_KEY_HEADER);

    if (!apiKey) {
      return sendError(res, req, 401, 'unauthorized', 'Missing or invalid API key.');
    }

    const client = getApiClientByHash(hashApiKey(apiKey));

    if (!client) {
      return sendError(res, req, 401, 'unauthorized', 'Missing or invalid API key.');
    }

    req.clientInfo = {
      clientId: client.client_id,
      name: client.name
    };
    req.apiKeyRaw = apiKey;
    next();
  };
}
