/**
 * Module purpose:
 * Provides Base64Url helpers used by secure request/response encoding.
 * The contract requires Base64Url without padding for transport fields.
 */

export function toBase64Url(buffer) {
  return Buffer.from(buffer)
	.toString('base64')
	.replace(/\+/g, '-')
	.replace(/\//g, '_')
	.replace(/=+$/g, '');
}

export function fromBase64Url(value) {
  if (typeof value !== 'string' || value.length === 0) {
	throw new Error('Base64Url value must be a non-empty string.');
  }

  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const paddingNeeded = normalized.length % 4;
  const padded = paddingNeeded === 0 ? normalized : normalized + '='.repeat(4 - paddingNeeded);

  return Buffer.from(padded, 'base64');
}

export function toBase64UrlJson(value) {
  return toBase64Url(Buffer.from(JSON.stringify(value), 'utf8'));
}

export function fromBase64UrlJson(value) {
  return JSON.parse(fromBase64Url(value).toString('utf8'));
}
