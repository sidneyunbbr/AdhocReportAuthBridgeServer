import express from 'express';
import config from './config.js';
import logger from './logger.js';
import { sendError } from './http.js';
import { requestRefMiddleware } from './middleware/requestRef.js';
import {
  httpsMiddleware,
  jsonParserMiddleware,
  postContentTypeMiddleware,
  sizeLimitMiddleware
} from './middleware/security.js';
import { apiKeyAuthMiddleware } from './middleware/apiKeyAuth.js';
import { createKeysRouter } from './routes/keys.js';
import { createValidateSecureRouter } from './routes/validateSecure.js';

export function createApp(appConfig = config) {
  const app = express();
  app.disable('x-powered-by');

  app.use(requestRefMiddleware);
  app.use(sizeLimitMiddleware(appConfig));
  app.use(httpsMiddleware(appConfig));
  app.use(postContentTypeMiddleware());
  app.use(jsonParserMiddleware(appConfig));

  app.use('/api/external-auth', createKeysRouter(appConfig));
  app.use('/api/external-auth', apiKeyAuthMiddleware(appConfig), createValidateSecureRouter(appConfig));

  app.use((req, res) => sendError(res, req, 404, 'not_found', 'Route not found.'));

  app.use((error, req, res, _next) => {
    logger.error('Unhandled application error.', {
      requestRef: req.requestRef,
      code: error.code,
      status: error.status,
      error: error.message
    });

    if (error.type === 'entity.too.large') {
      return sendError(res, req, 413, 'payload_too_large', 'Request payload exceeds the allowed size.');
    }

    if (error instanceof SyntaxError && 'body' in error) {
      return sendError(res, req, 400, 'invalid_json', 'Request body must contain valid JSON.');
    }

    return sendError(res, req, 500, 'internal_error', 'An internal server error occurred.');
  });

  return app;
}

export default createApp;
