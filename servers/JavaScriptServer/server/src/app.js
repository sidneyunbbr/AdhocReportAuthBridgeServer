/**
 * Module purpose:
 * Defines the Express application pipeline used by the integration server.
 * It wires payload parsers, registers AuthBridge routes, and provides fallback 404 handling.
 */
import express from 'express';
import externalAuthRouter from './routes/externalAuth.routes.js';

// Builds the Express app with shared middleware and external-auth routes.
export function createApp() {
  const app = express();

	// Parses JSON and form payloads used by contract requests.
  app.use(express.json({ limit: '1mb' }));
  app.use(express.urlencoded({ extended: false }));

	// AuthBridge contract surface for external authentication.
	app.use('/api/external-auth', externalAuthRouter);

	// Default not found response for unsupported paths.
  app.use((req, res) => {
	res.status(404).json({
	  message: 'Route not found',
	  path: req.path,
	  method: req.method
	});
  });

  return app;
}
