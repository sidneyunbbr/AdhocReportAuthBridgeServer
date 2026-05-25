export function sendError(res, req, status, code, message) {
  return res.status(status).json({
    error: code,
    message,
    requestRef: req.requestRef || 'unknown'
  });
}
