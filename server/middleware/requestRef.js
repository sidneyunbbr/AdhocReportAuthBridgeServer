import { randomUUID } from 'node:crypto';

export function requestRefMiddleware(req, res, next) {
  req.requestRef = randomUUID();
  res.setHeader('X-Request-Ref', req.requestRef);
  next();
}
