# Company Identity Platform

This repository defines a production-oriented **Keycloak-centric Identity Platform** for .NET 10. Keycloak is the authoritative Identity Provider and OAuth 2.0/OIDC Authorization Server. The .NET application is an Identity Facade / Identity Orchestrator for normalized APIs, Keycloak administration, proprietary organization SSO integration, permission registration, caching, audit, and integration concerns.

It does **not** implement passwords, credentials, sessions, MFA, access-token or refresh-token minting, token revocation, user federation, role semantics, or JWT signing. Application services accept genuine Keycloak-issued JWTs and validate them locally.

See [docs/architecture.md](docs/architecture.md) for the complete architecture, diagrams, ownership table, flows, extension design, threat model, cache policy, Vault key rotation, deployment model, and test strategy. See [docs/running.md](docs/running.md) for the step-by-step server run guide (compose up → login → call the facade and the order-service sample).

## Developer integration

```csharp
builder.Services
    .AddCompanyAuthentication(options =>
    {
        options.Authority = configuration["Identity:Authority"]!; // the facade URL
        options.Audience = configuration["Identity:Audience"]!;
        options.AcceptIssuerFromDiscovery = true; // issuer comes from the proxied discovery doc
    })
    .AddCompanyAuthorization();

builder.Services.AddPermissionRegistration(options =>
{
    options.IdentityServer = new Uri(configuration["PermissionRegistration:IdentityServer"]!);
    options.ServiceName = "order-service";
    options.ClientId = "order-service";
    options.ClientSecret = configuration["PermissionRegistration:ClientSecret"];
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

Permissions are mirrored by the facade into Keycloak **per-service client roles** (for example `orders-service: Orders.Cancel`), surfaced as the `permissions`/`permission` claims by one `oidc-usermodel-client-role-mapper` per client aggregating `resource_access.<client>.roles` → `permissions`. A newly registered permission is auto-mapped to the Admin Group (`key-admins`) and appears on the next refresh without re-login. Role provisioning and client-scope mapper creation are best-effort (409/race-safe) — a Keycloak outage never fails the registration response. Missing permissions are locally soft-deprecated, never deleted from Keycloak; drift is repaired via `POST /api/identity/permissions/reconcile-admin`.

## Run with Docker (Oracle 21 default)

```bash
cd deploy
docker compose up --build -d
# Oracle XE 21 (Keycloak DB + facade metadata), Keycloak 26.4, Vault, Redis,
# Identity Facade, and the order-service sample — all healthchecked.
```

Ports are overridable when the host already uses them: `FACADE_HTTP_PORT`,
`KEYCLOAK_HTTP_PORT`, `ORDER_HTTP_PORT` (defaults 5080/8080/5180).

Wait for the healthchecks (Oracle XE takes ~60s), then:

| Endpoint | URL |
| --- | --- |
| Identity Facade REST | http://localhost:5080 |
| Business roles / scoped access | `POST /api/identity/business-roles`, `POST /api/identity/users`, `GET /api/identity/access-context` (claim `iam_access`) |
| Scalar API reference (interactive, full Bearer "Try it" support) | http://localhost:5080/scalar |
| OpenAPI document | http://localhost:5080/openapi/v1.json |
| OIDC discovery + JWKS proxy (consumers point here) | http://localhost:5080/.well-known/openid-configuration |
| Keycloak Admin Console | http://localhost:8080 (realm `company`) |
| order-service sample | http://localhost:5180/api/orders |
| Vault dev UI | http://localhost:8200 (token `root`) |
| gRPC (IdentityService, KeyAdminService) | http://localhost:5080 |

**Services never see Keycloak.** A consumer points `Identity:Authority` at the facade; the
facade proxies OIDC discovery and rewrites `jwks_uri` to itself, and registration tokens are
obtained through the facade's login proxy. Keycloak's URL/realm/secrets exist only in the
facade's configuration.

Quick test sequence:

```bash
# 1. Login through the facade (Keycloak-issued token, never minted by .NET)
curl -s -X POST http://localhost:5080/api/identity/auth/login \
  -d "grant_type=password&client_id=identity-facade&client_secret=facade-development-only&username=admin&password=admin"

# 2. Call a protected facade route with the returned access_token
curl -s http://localhost:5080/api/identity/me -H "Authorization: Bearer <token>"

# 3. Call the sample service — its token comes from step 1, the audience already matches
curl -s http://localhost:5180/api/orders -H "Authorization: Bearer <token>"
```

Dev credentials: user `admin` / password `admin` (all `Identity.*` permissions).
CI/laptops that cannot run Oracle XE can fall back to PostgreSQL:

```bash
docker compose -f docker-compose.yml -f docker-compose.postgres.yml up --build -d
```

## External organization SSO

An opaque organization token is validated through a dedicated adapter or the recommended Keycloak custom OAuth2 Grant Type SPI. The token is never logged or unnecessarily persisted. The validated immutable `(provider, subject)` is linked to or provisions a Keycloak user, only allowlisted attributes are synchronized, external roles require explicit mappings, and Keycloak issues the final token. The facade never mints one.

A signed OIDC/JWT provider should use native Keycloak Identity Brokering where possible. JWT Authorization Grant support and limitations are release-specific and must be tested against the pinned Keycloak version. Deprecated legacy external Token Exchange is not the default.

## Key management

Keycloak signs JWTs with RSA keys. Vault is the source of truth through release-pinned Keycloak Vault/key-provider extensions. Key IDs are immutable and rotate by overlap, for example `iam-rsa-2026-09` to `iam-rsa-2026-12`; old public keys remain in JWKS until all relevant old tokens expire. The .NET service has no private signing-key store or JWKS endpoint.

## Business roles & scoped access

Business roles are **Keycloak Groups** (e.g. `/Admin`, `/Manager`); the facade's `IBusinessRoleStore` is `KeycloakGroupBusinessRoleStore`. Permissions are **per-service client roles** (e.g. `orders-service: Orders.Cancel`) aggregated into the `permissions` claim by one `oidc-usermodel-client-role-mapper` per client; new permissions are auto-mapped to the Admin Group (`key-admins`) and reconciled via `POST /api/identity/permissions/reconcile-admin` without re-login (refresh picks up `resource_access` → `permissions`).

Scoped assignments (`{role, scopes: {region:[...], branch:[...]}}`) are **Keycloak-attribute-driven, normalized and validated** against the dedicated config Group `/iam-scope-registry` (`scope.<key>` JSON `{displayName,description,isActive,valueType}` + `resource.<name>` multivalued, business-role Groups hold `authz.allowed-scopes`). User values live as multivalued attributes `authz.scope.<key>` (each value one entry), merged as Group ∪ User gated at write; the scalar `"test-key": "items-1"` form is normalized to `["items-1"]` via `ScopeDictionaryConverter`; unknown/inactive/disallowed scopes return field-level `400 ValidationProblem` (`assignments[0].scopes.test-key`). Oracle `identity-meta-db` retains only key/Vault metadata; legacy scope tables are kept `[Obsolete]` for `InMemoryDatabase` tests during migration (see `deploy/migrate-oracle-to-keycloak.sh`). The `authz-scopes` client scope exposes `authz.scope.*` as flat claims, hardened so only admins can write them via the User Profile. Filter safely in consumers via `ScopeFilterService.ApplyAsync(query, effectiveScopes, ResourceKeys.Orders)` — deny-by-default, parameterized `Contains`/`IN`, no `EF.Property` on client-supplied names. See `samples/OrderService.Sample` (`ScopeFilters.cs`, `/api/orders/scoped`).

### Adding a new scope (5 steps, no DTO change)

1. Seed `ScopeDefinition { Key = "cost-center" }` (or `POST /api/identity/scopes`). 2. Insert `ScopeResourceMapping(cost-center → Orders)`. 3. Optionally `RoleAllowedScope(role, cost-center)`. 4. Optionally register `IScopeValueValidator { ScopeKey = "cost-center" }`. 5. Register `IScopeFilterHandler<OrderDto> { ScopeKey = "cost-center", ResourceKey = ResourceKeys.Orders }` — unknown keys are rejected until step 1.

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

## Database(Oracle only provided) | Create user and schema for database queries

These queries provide schema, user and access to work service with database

```sql
CREATE USER IDENTITY_META IDENTIFIED BY "identity-development-only" QUOTA UNLIMITED ON USERS;
GRANT CONNECT, RESOURCE TO IDENTITY_META;
```