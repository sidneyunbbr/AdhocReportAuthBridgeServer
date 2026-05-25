# Secure envelope schema

## Request body

```json
{
  "keyId": "server-key-001",
  "clientId": "test-client-001",
  "requestId": "550e8400-e29b-41d4-a716-446655440000",
  "timestamp": 1735689600000,
  "clientPublicKey": "<base64 DER spki public key>",
  "signature": "<base64 HMAC-SHA256>",
  "encryptedPayload": "<base64 ciphertext>",
  "iv": "<24-char hex>",
  "authTag": "<base64 GCM tag>"
}
```

## Field rules

- `keyId`: string, required, must match the active server key.
- `clientId`: string, required, must match the API client authenticated by `x-api-key`.
- `requestId`: string, required, must be unique within replay TTL.
- `timestamp`: number, required, milliseconds since epoch.
- `clientPublicKey`: string, required, base64-encoded DER/SPKI P-256 public key.
- `signature`: string, required, base64 HMAC-SHA256 over `keyId|clientId|requestId|timestamp|clientPublicKey|encryptedPayload`.
- `encryptedPayload`: string, required, base64 AES-256-GCM ciphertext.
- `iv`: string, required, 12-byte IV encoded as hex.
- `authTag`: string, required, base64 GCM authentication tag.

## Decrypted payload

```json
{
  "username": "user1",
  "password": "password1"
}
```

## Success result plaintext

```json
{
  "authenticated": true,
  "username": "user1",
  "role": "user",
  "sessionRef": "550e8400-e29b-41d4-a716-446655440000"
}
```
