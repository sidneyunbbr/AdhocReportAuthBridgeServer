# Security notes

- API client authentication uses a raw API key sent in the configured header and matched by SHA-256 hash.
- Envelope integrity uses HMAC-SHA256 with the raw API key because this phase does not maintain a client public-key registry.
- Credential payloads and responses use AES-256-GCM with keys derived from P-256 ECDH + HKDF.
- Replay protection relies on `requestId` plus `REPLAY_TTL_SECONDS`; run replay cleanup regularly in long-lived deployments.
- The validation route applies a lightweight in-memory per-client rate limit to slow credential stuffing and API key abuse.
- Password storage uses salted SHA-256 for this dependency-free demo and is not a replacement for Argon2, scrypt, or bcrypt in production.
- Do not log credentials, raw API keys, private keys, decrypted payloads, or encrypted payload blobs.
- Enable `REQUIRE_HTTPS=true` in production and terminate TLS before exposing this service.
