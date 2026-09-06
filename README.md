# Company Identity Service

A .NET 10 Clean Architecture identity and access-management service with local authentication, JWT access tokens, rotating refresh tokens, BFF sessions, permission discovery, RabbitMQ manifests, REST, and gRPC.

## Solution layout

`IdentityService.slnx` groups the projects by responsibility:

- `src/Domain` — identity entities and invariants.
- `src/Application` — use cases and ports; no EF Core, ASP.NET Core, RabbitMQ, or provider dependencies.
- `src/Contracts` — REST and integration contracts.
- `src/Infrastructure` — cryptography, password hashing, JWT signing keys.
- `src/Persistence` — persistence abstractions and EF Core adapters.
- `src/Messaging` — messaging contracts and RabbitMQ adapter.
- `src/Providers` — local, OIDC, and Keycloak provider adapters.
- `src/Packages` — independently consumable authentication, authorization, permission-discovery, and gRPC packages.
- `src/Host` — the `Identity.Api` composition root.
- `samples` — an external-service integration sample.
- `tests` — unit, architecture, API, messaging, and persistence tests.

## Build and test

```bash
dotnet restore IdentityService.slnx
dotnet build IdentityService.slnx
dotnet test IdentityService.slnx
```

## Database providers

The EF Core adapter supports SQLite, PostgreSQL, and Oracle. Select the provider with `Identity:Persistence:Provider` and supply `ConnectionStrings:Identity` through environment variables or a secret provider:

```json
{
  "ConnectionStrings": {
    "Identity": "Host=localhost;Port=5433;Database=identity;Username=identity;Password=${IDENTITY_DB_PASSWORD}"
  },
  "Identity": {
    "Persistence": { "Provider": "PostgreSql" }
  }
}
```

Accepted provider names are `Sqlite`, `PostgreSql`/`Postgres`, and `Oracle`. The development settings use SQLite. Production and Compose use PostgreSQL by default. Oracle support requires an Oracle database and the Oracle EF Core provider; no Oracle container is included in this repository.

### EF migrations

The design-time factory uses environment variables and does not start the API:

```bash
# SQLite (default; creates the ignored identity-design-time.db if updated)
IDENTITY_DESIGN_TIME_PROVIDER=sqlite \
  dotnet ef migrations list --project src/Identity.Persistence.EntityFrameworkCore

# PostgreSQL
IDENTITY_DESIGN_TIME_PROVIDER=postgres \
IDENTITY_DESIGN_TIME_CONNECTION="Host=localhost;Port=5433;Database=identity;Username=identity;Password=$IDENTITY_DB_PASSWORD" \
  dotnet ef migrations list --project src/Identity.Persistence.EntityFrameworkCore

# Oracle
IDENTITY_DESIGN_TIME_PROVIDER=oracle \
IDENTITY_DESIGN_TIME_CONNECTION="$ORACLE_CONNECTION_STRING" \
  dotnet ef migrations list --project src/Identity.Persistence.EntityFrameworkCore
```

Use a separate migration assembly/history per provider when generated SQL differs. Never commit connection strings, private signing keys, Data Protection keys, or local database files.

## PostgreSQL with Docker Compose

Start the database-only stack on host port `5433`:

```bash
export IDENTITY_DB_PASSWORD='use-a-local-secret'
docker compose -f deploy/docker-compose.postgres.yml up -d
docker compose -f deploy/docker-compose.postgres.yml ps
```

After the healthcheck reports `healthy`, run the API with `ConnectionStrings__Identity` pointing to `localhost:5433`, or start the complete stack:

```bash
docker compose -f deploy/docker-compose.yml up --build
```

The full stack includes PostgreSQL, RabbitMQ, and the API. Override `IDENTITY_DB_PASSWORD` and `RABBITMQ_PASSWORD`; the Compose fallbacks are for local development only.

## REST API

The identity API exposes:

- `POST /api/auth/login` — local login and access/refresh token issuance.
- `POST /api/auth/refresh` — refresh-token rotation.
- `POST /api/auth/logout` and `/api/auth/logout-all` — session revocation.
- `GET /api/users/me` — current user, roles, permissions, and session.
- `GET /.well-known/jwks.json` — JWT public signing keys.
- `GET /health/live` — liveness check.

Use `Authorization: Bearer <access-token>` for protected REST calls. Browser applications should use the BFF cookie flow instead of storing bearer tokens in JavaScript storage.

## gRPC API

The same identity use cases are available through `company.identity.v1.IdentityService`:

- `Login`
- `Refresh`
- `Logout`
- `GetCurrentUser`

The service is mapped by `Identity.Api` and supports HTTP/2 on the HTTPS endpoint. Send the bearer token as lowercase `authorization` metadata for protected calls.

## Use the packages in another service

For a service that only validates identity tokens:

```xml
<ItemGroup>
  <PackageReference Include="Company.Identity.Authentication.AspNetCore" Version="1.0.0" />
</ItemGroup>
```

```csharp
using Company.Identity.Authentication;
using Company.Identity.Authentication.AspNetCore;

builder.Services.AddCompanyAuthentication(new IdentityAuthenticationOptions
{
    Authority = builder.Configuration["Identity:Authority"]!,
    Audiences = [builder.Configuration["Identity:Audience"]!],
    RequireHttpsMetadata = !builder.Environment.IsDevelopment()
});

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();
app.MapGet("/api/orders", () => Results.Ok())
   .RequireAuthorization();
```

For permission-based authorization, add:

```xml
<ItemGroup>
  <PackageReference Include="Company.Identity.Authorization.AspNetCore" Version="1.0.0" />
  <PackageReference Include="Company.Identity.PermissionDiscovery" Version="1.0.0" />
</ItemGroup>
```

```csharp
using Company.Identity.Abstractions;
using Company.Identity.Authorization.AspNetCore;

builder.Services.AddCompanyAuthorization();

app.MapGet("/api/orders", () => Results.Ok())
   .RequireAuthorization("orders.read");

[RequirePermission("orders.read")]
public sealed class OrdersEndpoint;
```

`RequirePermissionAttribute` is also discovered by `PermissionDiscovery`, allowing a service to publish its permission manifest while enforcing the same permission in its API.

### Forward the current token to the identity API

For server-to-server calls made while handling an authenticated request, register the built-in forwarding client:

```csharp
builder.Services.AddIdentityApiClient(
    new Uri(builder.Configuration["Identity:BaseUrl"]!));

app.MapGet("/api/who-am-i", async (IHttpClientFactory clients, CancellationToken cancellationToken) =>
{
    var response = await clients.CreateClient("IdentityApi")
        .GetAsync("/api/users/me", cancellationToken);
    return Results.StatusCode((int)response.StatusCode);
}).RequireAuthorization();
```

The handler copies only a validated inbound Bearer header. It does not log, persist, or expose the token. For gRPC, add the same token to call metadata:

```csharp
var headers = new Grpc.Core.Metadata
{
    { "authorization", $"Bearer {accessToken}" }
};
var current = await identityClient.GetCurrentUserAsync(
    new CurrentUserRequest(), headers: headers);
```

The `samples/Identity.Consumer.Api` project demonstrates configuration, an attributed protected endpoint, REST forwarding, and gRPC consumption.

## Security and operations

- Access tokens are short-lived RSA-signed JWTs; publish the JWKS endpoint to consumers.
- Refresh tokens are random, rotated, hashed before persistence, and revoked on reuse.
- BFF sessions are Secure, HttpOnly, SameSite cookies backed by server-side sessions and antiforgery tokens.
- Keep signing-key and Data Protection directories persistent across restarts and use KMS/HSM-backed storage for multi-replica production deployments.
- Do not grant privileged roles from external provider claims without an explicit mapping.
- Replace all development passwords and configure TLS, secret management, logging redaction, and database backups before production.
