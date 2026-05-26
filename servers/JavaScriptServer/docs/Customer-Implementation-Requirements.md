# Customer Implementation Requirements (JavaScript Reference)

This document clarifies what a customer authorization server must implement to be compatible with AdhocReport secure validation flow.

## 1) Shared API key (mandatory)
- The API key used in request headers is a **shared secret** between AdhocReport and the customer authorization server.
- Requests without a valid key must be rejected.

### Where to configure this key

Use the exact same value in both systems.

#### AdhocReport side (caller)
- Configure AuthBridge request API key in AdhocReport configuration (`appsettings` or environment variables).

#### Customer server side (receiver)
- Configure:
  - `AUTHBRIDGE_REQUEST_API_KEY=<shared-secret>`
  - `AUTHBRIDGE_REQUIRE_REQUEST_API_KEY=true`

Default header name expected by this JavaScript server:
- `X-Bridge-Api-Key`

Header distinction for AdhocReport.AuthBridge.Api users:
- `RequestApiKeyHeaderName` must map to the receiver-side header used here (default `X-Bridge-Api-Key`).
- `ApiKeyHeaderName` (commonly `X-Api-Key`) is typically used for downstream API calls and is a separate configuration concern.

Optional customization:
- `AUTHBRIDGE_REQUEST_API_KEY_HEADER_NAME` can change header name when needed.

## 2) Replay protection storage (mandatory)
To prevent replay attacks, the server must persist processed request fingerprints.

Minimum persisted fields:
- `clientId`
- `requestId`
- request timestamp
- creation timestamp
- expiration timestamp (TTL)

Rule:
- (`clientId`, `requestId`) must be unique while valid.
- If a request arrives with a pair already seen in the valid window, reject it (`replay detected`).

Important for customers:
- This persistence is mandatory (database table or equivalent durable storage).
- Without this storage, replay protection is incomplete and insecure.
- The server should provide a safe way to reset/reseed test data for local validation scenarios.

### Example table shape (SQLite style)
```sql
CREATE TABLE replay_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  client_id TEXT NOT NULL,
  request_id TEXT NOT NULL,
  request_timestamp_utc TEXT NOT NULL,
  created_at_utc TEXT NOT NULL,
  expires_at_utc TEXT NOT NULL,
  UNIQUE(client_id, request_id)
);
```

## 3) Timestamp freshness (mandatory)
- Validate `timestampUtc` against an accepted clock skew window.
- Expired/out-of-window requests must be rejected.

## 4) Deterministic error behavior (mandatory)
The server should return deterministic transport errors for pre-crypto checks, for example:
- `401` unauthorized caller
- `422` unsupported protocol
- `400` malformed envelope
- `408` expired request window
- `409` replay detected

## 5) Cryptographic phase (mandatory)
After prechecks pass, the server must execute cryptographic validation and processing:
- signature verification
- key agreement/derivation
- decrypt request payload
- encrypt response payload
- sign secure response envelope

This JavaScript reference now includes a full secure response pipeline with conformance tests and example client flow.

## Quick local setup for customer tests (PowerShell)

Use this to validate local startup quickly with shared key + secure protocol.

```powershell
cd E:\PROJETOS\AdhocReport_SRV\IntegrationServers\AdhocReportAuthBridgeServer\servers\JavaScriptServer
npm install

$env:AUTHBRIDGE_REQUEST_API_KEY="ADLK40308$$55DLD-DKDLLKDLL23093DL"
$env:AUTHBRIDGE_REQUIRE_REQUEST_API_KEY="true"
$env:AUTHBRIDGE_SECURE_PROTOCOL_VERSION="2.0"

# Optional reset/reseed for local test data
$env:AUTHBRIDGE_RESET_SHARED_DATA_ON_START="true"
npm run reseed-data

npm run start
```

Smoke check from another terminal:

```powershell
Invoke-WebRequest -Uri "http://localhost:3000/api/external-auth/health" -Method Get
Invoke-WebRequest -Uri "http://localhost:3000/api/external-auth/keys" -Method Get
```

Run the secure round-trip example client:

```powershell
node examples/secure-roundtrip-client.js
```

Run conformance tests:

```powershell
npm run test:conformance
```

Important:
- After first run with reset enabled, set `AUTHBRIDGE_RESET_SHARED_DATA_ON_START` to `false` (or remove it).
- Keep the same shared key configured on AdhocReport caller side and on customer server side.