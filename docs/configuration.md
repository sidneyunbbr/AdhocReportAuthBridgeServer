# Configuration

| Variable | Type | Default | Description |
| --- | --- | --- | --- |
| `PORT` | integer | `3000` | HTTP listen port. |
| `NODE_ENV` | string | `development` | Runtime environment label. |
| `DB_PATH` | string | `./data/authbridge.db` | SQLite database location. |
| `API_KEY_HEADER` | string | `x-api-key` | Header used for API key authentication. |
| `MAX_PAYLOAD_BYTES` | integer | `65536` | Maximum accepted request body size. |
| `TIMESTAMP_TOLERANCE_SECONDS` | integer | `300` | Allowed clock skew for secure envelopes. |
| `REPLAY_TTL_SECONDS` | integer | `600` | Replay cache retention window. |
| `REQUIRE_HTTPS` | boolean | `false` | Reject plain HTTP when enabled. |
| `LOG_LEVEL` | string | `info` | Structured logger threshold: `debug`, `info`, `warn`, `error`. |
| `SERVER_CURVE` | string | `P-256` | Informational curve name for server keys. |
| `PROTOCOL_VERSION` | string | `1.0` | Protocol version reported by `/keys`. |
