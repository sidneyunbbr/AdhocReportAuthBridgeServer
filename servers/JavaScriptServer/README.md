# JavaScriptServer (AuthBridge Reference)

This directory contains the JavaScript reference implementation of the external authorization server contract used by AdhocReport.

## Should we create this README now or only when everything is done?

Recommendation: **create now and keep it versioned from the beginning**.

Reason: this server is already customer-facing, and the adaptation points are spread across validator, service, crypto, config, and data files. Having the map now reduces onboarding errors.

You are right that line numbers require maintenance. This README is intentionally explicit and should be updated whenever relevant code changes.

---

## Customer adaptation map (file + line)

> Line numbers below refer to the current repository state and must be reviewed after edits.

### 1) Shared security policy and headers

- **File:** `server/src/config/securityConfig.js`
- **Lines:** `27-59`
- **What customer usually adapts:**
  - protocol version (`secureProtocolVersion`)
  - header names (`requestApiKeyHeaderName`, `protocolHeaderName`, `correlationIdHeaderName`)
  - replay/timestamp windows (`maxClockSkewSeconds`, `replayTtlSeconds`)
  - algorithm labels (`keyAgreementCurve`, `kdfAlgorithm`, `contentEncryption`, `signatureAlgorithm`, `kdfInfo`)
- **Why it matters:**
  - This is the source of truth consumed by request validation and secure processing.

---

### 2) Request pre-validation and replay protection

- **File:** `server/src/validation/secureEnvelopeValidator.js`
- **Lines:** `55-119`
- **What customer usually adapts:**
  - strictness of prechecks
  - replay strategy integration with customer storage
  - additional request-level policy checks
- **Why it matters:**
  - This module rejects invalid/unsafe traffic before expensive crypto operations.
- **Related files:**
  - `server/src/config/securityConfig.js` (policy)
  - `server/src/data/replayRepository.js` + `server/src/data/sqlite.js` (durable replay store)

---

### 3) Business authentication decision (main customization point)

- **File:** `server/src/services/authDecisionService.js`
- **Lines:**
	- `82-108` (decrypted payload validation)
  - `110-132` (authentication decision and contract business payload)
- **What customer usually adapts:**
  - user lookup and credential validation logic
  - account status checks
  - additional authorization rules / claims composition
- **Why it matters:**
	- This module is intentionally isolated from crypto plumbing so customers can replace business logic without breaking transport security.

---

### 4) Secure orchestration pipeline (keep stable)

- **File:** `server/src/services/secureValidationService.js`
- **Lines:**
	- `70-98` (protocol/key/signature/decrypt preconditions)
  - `100-104` (delegation to auth decision module)
  - `108-138` (response envelope encryption + signature)
- **What customer usually adapts:**
  - rarely; mainly for orchestration/observability extensions.
- **Why it matters:**
  - This is the contract-safe orchestration layer connecting validator, crypto, and auth decision services.

---

### 5) User lookup source

- **File:** `server/src/services/authDecisionService.js`
- **Lines:** `63-74`
- **and** `server/src/data/sqlite.js`
- **Lines:** `208-214`
- **What customer usually adapts:**
  - replace demo SQLite lookup with customer database/identity provider
  - keep same contract output fields (`externalUserId`, `email`, `fullName`, etc.)

---

### 6) Key lifecycle / rotation model

- **File:** `server/src/crypto/keyStore.js`
- **Lines:**
	- `79-127` (default keyring shape + keyring load/validation)
  - `141-165` (resolve encryption/signature private keys by `keyId`)
  - `193-211` (supported keyId checks)
  - `225-258` (published key discovery payload)
- **What customer usually adapts:**
  - replace demo key persistence with customer KMS/HSM/secrets strategy
  - rotation and trust-window policies
- **Why it matters:**
  - `keyId` and `signatureKeyId` drive decryption/signature verification compatibility.

---

### 7) Crypto implementation details

- **File:** `server/src/crypto/secureEnvelopeCrypto.js`
- **Lines:**
  - `5-32` (`deriveRequestKey`)
  - `35-57` (`decryptRequestPayload`)
  - `60-87` (`encryptResponsePayload`)
- **File:** `server/src/crypto/signature.js`
- **Lines:**
  - `11-27` (request canonical signing input)
  - `30-45` (response canonical signing input)
  - `48-54` (verify request signature)
  - `57-61` (sign response)
- **What customer usually adapts:**
  - usually **do not** change algorithms/field order unless both sides are versioned together.
- **Why it matters:**
  - Any mismatch here breaks interoperability.

---

### 8) HTTP surface and processing chain

- **File:** `server/src/routes/externalAuth.routes.js`
- **Lines:**
  - `15-21` (`/health`)
  - `24-26` (`/keys`)
  - `29-53` (`/validate-secure` chain)
- **What customer usually adapts:**
  - route hosting/infrastructure concerns, telemetry, request logging policy
  - keep endpoint contract unchanged for compatibility.

---

### 9) Shared test/demo data bootstrap

- **File:** `server/src/data/sqlite.js`
- **Lines:**
  - `31-55` (schema)
  - `57-66` (reset logic)
  - `68-126` (seed users)
- **File:** `scripts/reseed-shared-data.js`
- **Lines:** `8-12`
- **What customer usually adapts:**
  - seed users and reset strategy for local/test environments

---

### 10) Interoperability example client

- **File:** `examples/secure-roundtrip-client.js`
- **Lines:**
  - `101-118` (key discovery + X25519 handshake)
  - `149-176` (signed + encrypted request)
  - `185-196` (response signature validation)
  - `198-214` (response decryption)
- **What customer usually adapts:**
  - use this as reference for non-Node implementations.

---

### 11) Conformance safety net

- **File:** `server/tests/secure-endpoint.conformance.test.js`
- **Lines:**
  - `187-202` missing API key
  - `204-220` unsupported protocol
  - `222-250` replay detection
  - `252-293` valid secure round-trip
- **What customer usually adapts:**
  - extend with tenant-specific scenarios, but keep baseline tests.

---

## Practical maintenance rule for this README

Whenever any of the files above changes in structure, update this README in the same commit:

1. verify listed line ranges;
2. verify adaptation notes still match behavior;
3. keep cross-file links current.

This keeps customer teams able to perform surgical changes with low risk.
