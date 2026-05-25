import express from 'express';
import config from '../config.js';
import { sendError } from '../http.js';

export function sizeLimitMiddleware(appConfig = config) {
  return (req, res, next) => {
    const contentLength = Number(req.headers['content-length'] || 0);

    if (Number.isFinite(contentLength) && contentLength > appConfig.MAX_PAYLOAD_BYTES) {
      return sendError(res, req, 413, 'payload_too_large', 'Request payload exceeds the allowed size.');
    }

    next();
  };
}

export function httpsMiddleware(appConfig = config) {
  return (req, res, next) => {
    if (!appConfig.REQUIRE_HTTPS) {
      return next();
    }

    const forwardedProto = req.headers['x-forwarded-proto'];
    const isHttps = req.secure || forwardedProto === 'https';

    if (!isHttps) {
      return sendError(res, req, 400, 'https_required', 'HTTPS is required for this endpoint.');
    }

    next();
  };
}

export function postContentTypeMiddleware() {
  return (req, res, next) => {
    if (req.method !== 'POST') {
      return next();
    }

    if (!req.is('application/json')) {
      return sendError(res, req, 415, 'invalid_content_type', 'Content-Type must be application/json.');
    }

    next();
  };
}

export function jsonParserMiddleware(appConfig = config) {
  return express.json({ limit: appConfig.MAX_PAYLOAD_BYTES });
}
