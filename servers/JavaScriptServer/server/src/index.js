/**
 * Module purpose:
 * Entry point of the JavaScript integration server.
 * It loads environment variables, builds the Express app, and starts the HTTP listener.
 */
import dotenv from 'dotenv';
import { createApp } from './app.js';

// Loads environment variables from .env for local development and examples.
dotenv.config();

const app = createApp();
const port = Number(process.env.PORT || 3000);

// Starts the HTTP API entrypoint for the JavaScript integration server.
app.listen(port, () => {
  console.log(`[AuthBridge JS Server] Listening on port ${port}`);
});
