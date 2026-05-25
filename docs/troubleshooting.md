# Troubleshooting

- **`unauthorized`**: verify the `x-api-key` value matches the seeded client secret.
- **`timestamp_expired`**: confirm client and server clocks are in sync.
- **`signature_invalid`**: ensure the canonical string order is exactly `keyId|clientId|requestId|timestamp|clientPublicKey|encryptedPayload`.
- **`decryption_failed`**: confirm the client uses the server public key from `/keys`, the same `requestId` as HKDF salt, and a 12-byte IV.
- **`authentication_failed`**: verify local usernames and passwords (`admin/admin123`, `user1/password1`).
- **SQLite errors**: run `node data/reset.js` to rebuild the database from scratch.
