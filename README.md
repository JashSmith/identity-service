# Company Identity Platform

This repository defines a production-oriented **Keycloak-centric Identity Platform** for .NET 10. Keycloak is the authoritative Identity Provider and OAuth 2.0/OIDC Authorization Server. The .NET application is an Identity Facade / Identity Orchestrator for normalized APIs, Keycloak administration, proprietary organization SSO integration, permission registration, caching, audit, and integration concerns.

It does **not** implement passwords, credentials, sessions, MFA, access-token or refresh-token minting, token revocation, user federation, role semantics, or JWT signing. Application services accept genuine Keycloak-issued JWTs and validate them locally.

See [docs/architecture.md](docs/architecture.md) for the complete architecture, diagrams, ownership table, flows, extension design, threat model, cache policy, Vault key rotation, deployment model, and test strategy.

## Developer integration

```csharp
builder.Services
    .AddCompanyAuthentication(options =>
    {
        options.Authority = configuration["Identity:Authority"]!;
        options.Audience = configuration["Identity:Audience"]!;
    })
    .AddCompanyAuthorization();

builder.Services.AddPermissionRegistration(options =>
{
    options.IdentityServer = new Uri(configuration["PermissionRegistration:IdentityServer"]!);
    options.ServiceName = "order-service";
    options.KeycloakBaseUrl = "http://localhost:8080";
    options.KeycloakClientId = "order-service";
    options.KeycloakClientSecret = configuration["PermissionRegistration:KeycloakClientSecret"];
});
```

A complete working consumer — ten `[RequirePermission]`-guarded endpoints plus the
startup registration wiring — lives in [samples/OrderService.Sample](samples/OrderService.Sample/).

Protect an operation with a stable application permission:

```csharp
[RequirePermission("Orders.Cancel")]
public Task<IActionResult> Cancel(CancellationToken cancellationToken) => ...;
```

Authentication and authorization are independently installable. Authentication performs local issuer, audience, signature, expiration, not-before, algorithm, and token-type validation using Keycloak discovery and JWKS. It does not call the facade on every request. Authorization evaluates trusted Keycloak role/permission claims locally.

## Permission registration

`Company.Identity.PermissionRegistration` discovers permission metadata, creates a deterministic manifest hash, and registers directly with the facade over REST using Keycloak client credentials. Registration is idempotent, namespace-scoped, retryable in the background (exponential backoff, default 8 retries), and never blocks application startup. RabbitMQ is not part of permission registration.

Permissions are mirrored by the facade into Keycloak **realm roles** (for example `Orders.Cancel`), so the existing `oidc-usermodel-realm-role-mapper` surfaces them in the `permissions`/`permission` token claims that `Company.Identity.Authorization` evaluates locally. Role provisioning is best-effort — a Keycloak outage never fails the registration response. Missing permissions are deprecated, not automatically deleted, and deprecation never removes the Keycloak role.

## Run with Docker (Oracle 21 default)

```bash
cd deploy
docker compose up --build -d        # Oracle XE 21 for Keycloak + facade metadata, Keycloak 26.4, Vault, Redis
```

Wait for the healthchecks (Oracle XE takes ~60s), then:

| Endpoint | URL |
| --- | --- |
| Identity Facade REST | http://localhost:5080 |
| Scalar API reference (interactive, full Bearer "Try it" support) | http://localhost:5080/scalar |
| OpenAPI document | http://localhost:5080/openapi/v1.json |
| Keycloak Admin Console | http://localhost:8080 (realm `company`, admin/admin) |
| Vault dev UI | http://localhost:8200 (token `root`) |
| gRPC (IdentityService, KeyAdminService) | http://localhost:5080 |

In Scalar, click **Authenticate**, paste a Keycloak-issued JWT, and call any group:
Auth (login/refresh/introspect/logout), Users, Roles, Permissions, Keys (Admin).
Dev credentials: user `admin` / password `admin` (all `Identity.*` permissions), or a
client-credentials token for client `identity-facade` (secret `facade-development-only`).

CI/laptops that cannot run Oracle XE can fall back to PostgreSQL:

```bash
docker compose -f docker-compose.yml -f docker-compose.postgres.yml up --build -d
```

## External organization SSO

An opaque organization token is validated through a dedicated adapter or the recommended Keycloak custom OAuth2 Grant Type SPI. The token is never logged or unnecessarily persisted. The validated immutable `(provider, subject)` is linked to or provisions a Keycloak user, only allowlisted attributes are synchronized, external roles require explicit mappings, and Keycloak issues the final token. The facade never mints one.

A signed OIDC/JWT provider should use native Keycloak Identity Brokering where possible. JWT Authorization Grant support and limitations are release-specific and must be tested against the pinned Keycloak version. Deprecated legacy external Token Exchange is not the default.

## Key management

Keycloak signs JWTs with RSA keys. Vault is the source of truth through release-pinned Keycloak Vault/key-provider extensions. Key IDs are immutable and rotate by overlap, for example `iam-rsa-2026-09` to `iam-rsa-2026-12`; old public keys remain in JWKS until all relevant old tokens expire. The .NET service has no private signing-key store or JWKS endpoint.

## Build and test

The environment must have the .NET 10 SDK and container runtime available:

```bash
dotnet restore IdentityService.slnx
dotnet build IdentityService.slnx
dotnet test IdentityService.slnx
```

Integration tests use Testcontainers for the pinned Keycloak, PostgreSQL, Redis, and organization validation stub. Extension compatibility tests run separately against the pinned and next supported Keycloak releases.

## Operational non-goals

- No second user/credential/session/token database.
- No custom JWT issuer in .NET.
- No raw-token, password, private-key, or Vault-secret logging.
- No remote authorization call on every normal application request.
- No automatic privilege assignment from external roles.
- No automatic deletion of permissions from a manifest.
