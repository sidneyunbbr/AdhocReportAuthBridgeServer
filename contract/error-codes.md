# Error codes

| HTTP status | Error code | Description |
| --- | --- | --- |
| 400 | `invalid_envelope` | Missing fields, malformed values, or unknown key identifier. |
| 400 | `invalid_json` | Request body is not valid JSON. |
| 400 | `https_required` | HTTPS is required when `REQUIRE_HTTPS=true`. |
| 401 | `unauthorized` | API key is missing, invalid, or bound to a different client ID. |
| 401 | `authentication_failed` | Local username/password validation failed. |
| 404 | `not_found` | Route does not exist. |
| 408 | `timestamp_expired` | Request timestamp is outside the allowed tolerance window. |
| 409 | `replay_detected` | `requestId` was already processed inside replay TTL. |
| 413 | `payload_too_large` | Request body exceeded `MAX_PAYLOAD_BYTES`. |
| 429 | `rate_limited` | Too many validation attempts were made in a short window. |
| 415 | `invalid_content_type` | POST requests must use `application/json`. |
| 422 | `signature_invalid` | HMAC signature verification failed. |
| 422 | `decryption_failed` | AES-GCM decryption or payload parsing failed. |
| 500 | `internal_error` | Unhandled server-side failure. |
