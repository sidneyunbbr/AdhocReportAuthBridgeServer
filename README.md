# AdhocReportAuthBridgeServer

Reference integration servers for external authentication in the AdhocReport ecosystem.

## Purpose
This repository exists to show customers how to implement a compatible authorization server in their own platform.

## Contract-first rule
- The protocol contract is the source of truth.
- Implementations in different languages must behave the same at the HTTP/protocol/security level.

## Current implementation focus
- `servers/JavaScriptServer` (Node.js) is the active first reference implementation.

## Mandatory security notes for customers
1. **Shared API key is required**
   - The request API key is a shared secret between AdhocReport and the customer authorization server.
2. **Replay protection is required**
   - The customer must persist request fingerprints (`clientId` + `requestId`) with expiration/TTL.
   - Repeated requests with the same pair must be rejected.
3. **Timestamp freshness is required**
   - Requests outside the accepted time window must be rejected.

## Where to configure the shared API key

Use the same secret value on both sides.

### In AdhocReport (caller)
- Configure the value in AdhocReport AuthBridge settings (appsettings/environment) for request API key usage.

### In customer authorization server (receiver)
- Configure environment variable:
  - `AUTHBRIDGE_REQUEST_API_KEY=<shared-secret>`
- Keep validation enabled:
  - `AUTHBRIDGE_REQUIRE_REQUEST_API_KEY=true`

### Header used on requests
- Default header name is `X-Bridge-Api-Key`.
- If needed, override header name in the server with `AUTHBRIDGE_REQUEST_API_KEY_HEADER_NAME`.

## Quick local setup (PowerShell)

### 1) Open JavaScript server folder
```powershell
cd E:\PROJETOS\AdhocReport_SRV\IntegrationServers\AdhocReportAuthBridgeServer\servers\JavaScriptServer
```

### 2) Install dependencies
```powershell
npm install
```

### 3) Configure shared API key and secure protocol
```powershell
$env:AUTHBRIDGE_REQUEST_API_KEY="ADLK40308$$55DLD-DKDLLKDLL23093DL"
$env:AUTHBRIDGE_REQUIRE_REQUEST_API_KEY="true"
$env:AUTHBRIDGE_SECURE_PROTOCOL_VERSION="2.0"
```

### 4) (Optional) reset and reseed shared test data
```powershell
$env:AUTHBRIDGE_RESET_SHARED_DATA_ON_START="true"
```

### 5) Run server
```powershell
npm run start
```

### 6) Smoke checks
```powershell
Invoke-WebRequest -Uri "http://localhost:3000/api/external-auth/health" -Method Get
Invoke-WebRequest -Uri "http://localhost:3000/api/external-auth/keys" -Method Get
```

After one startup with reset enabled, set this variable back to false (or remove it) to avoid wiping data on every run.

See details and an implementation-oriented checklist in:
- `servers/JavaScriptServer/docs/Customer-Implementation-Requirements.md`
