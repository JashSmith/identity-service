# Enterprise Identity Service

A .NET 10 Clean Architecture foundation for a reusable Identity and Access Management platform.

## Current foundation

- Provider-independent domain and application contracts.
- Independent authentication and authorization packages.
- Permission attributes and reflection-based manifest discovery.
- JWT bearer configuration adapter for consuming APIs.
- Initial protected current-user endpoint and health endpoint.
- Deterministic domain/application/architecture tests.

## Security direction

Access tokens are intended to be short-lived and signed asymmetrically with rotated keys. Refresh tokens must be stored only as hashes and rotated with family reuse detection. Browser clients should use an opaque, Secure, HttpOnly, SameSite session cookie through a BFF rather than exposing bearer tokens to JavaScript. Permission manifests are versioned and synchronized idempotently; removed permissions are deprecated rather than silently deleted.

This workspace is being built incrementally. Persistence, concrete token issuance, provider adapters, messaging, and full integration/deployment assets are subsequent phases and must not be treated as production-complete until their tests and operational configuration are present.

## Build and test

```bash
dotnet restore IdentityService.slnx
dotnet build IdentityService.slnx
dotnet test IdentityService.slnx
```


## Resume Claude task
```bash
claude --resume 80d4fe4e-a1fe-4776-952d-750cc99a65c6
```