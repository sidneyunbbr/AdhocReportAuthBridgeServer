# AdhocReportAuthBridgeServer

AdhocReportAuthBridgeServer is a Node.js ESM Express service that validates external credentials through an encrypted envelope protocol backed by SQLite.

## Quick start

```bash
npm install
node data/reset.js
npm start
```

Default demo credentials:

- API client: `test-client-001`
- API key: `test-api-key-secret-001`
- Users: `admin/admin123`, `user1/password1`

## Endpoints

- `GET /api/external-auth/keys`
- `POST /api/external-auth/validate-secure`

## Docs

- [Quickstart](docs/quickstart.md)
- [Configuration](docs/configuration.md)
- [Endpoints](docs/endpoints.md)
- [Security](docs/security.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Protocol flow](contract/protocol-flow.md)
- [Envelope schema](contract/secure-envelope-schema.md)
- [Error codes](contract/error-codes.md)
