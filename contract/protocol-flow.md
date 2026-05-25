# Protocol flow

```text
Client                           Server
  |                                |
  | GET /api/external-auth/keys    |
  |------------------------------->|
  |  active key metadata + PEM     |
  |<-------------------------------|
  |                                |
  | generate ephemeral P-256 key   |
  | derive shared secret           |
  | encrypt credentials            |
  | sign canonical string (HMAC)   |
  |                                |
  | POST /validate-secure envelope |
  |------------------------------->|
  | verify API key                 |
  | verify timestamp               |
  | verify replay cache            |
  | verify HMAC                    |
  | derive shared secret           |
  | decrypt payload                |
  | validate local user            |
  | store replay marker            |
  | encrypt result                 |
  |<-------------------------------|
  | encrypted authentication reply |
```

1. Client fetches the active server key.
2. Client generates an ephemeral P-256 key pair.
3. Client derives a shared secret using server public key + client private key.
4. Client encrypts credentials with AES-256-GCM using an HKDF-derived key.
5. Client signs the envelope with HMAC-SHA256 using the raw API key.
6. Server authenticates the API key, verifies timestamp and replay state, then verifies the HMAC.
7. Server derives the same AES key using its private key and the client public key.
8. Server decrypts credentials, authenticates the user, and returns an encrypted response.
