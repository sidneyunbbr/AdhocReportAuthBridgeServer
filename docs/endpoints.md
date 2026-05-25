# Endpoints

## GET `/api/external-auth/keys`

Returns the active server key metadata and PEM public key.

## POST `/api/external-auth/validate-secure`

Authenticates an encrypted credential envelope.

Required headers:

- `content-type: application/json`
- `x-api-key: <raw api key>`

Success response:

```json
{
  "status": "success",
  "encryptedResult": "<base64>",
  "iv": "<hex>",
  "authTag": "<base64>"
}
```

Error responses always include:

```json
{
  "error": "signature_invalid",
  "message": "Envelope signature verification failed.",
  "requestRef": "..."
}
```
