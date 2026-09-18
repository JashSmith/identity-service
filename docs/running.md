# Running the Identity Platform with the order-service Sample

Step-by-step operator guide: bring the full stack up on a server, watch it come healthy,
log in, and call both APIs. Everything below is verified against the committed code.

## What `docker compose up` starts

| Service | Image | Purpose |
| --- | --- | --- |
| `keycloak-db` | `gvenzl/oracle-xe:21-slim` | Oracle 21 XE — Keycloak's user/realm database |
| `identity-meta-db` | `gvenzl/oracle-xe:21-slim` | Oracle 21 XE — facade key-metadata DB (signing keys, rotation ops) |
| `keycloak` | custom (Keycloak 26.4 + ojdbc11 21.9) | Identity Provider — users, credentials, sessions, token issuance, signing keys |
| `identity-facade` | `deploy/Identity.Api.Dockerfile` | Identity Facade — auth proxy, directory, permissions, key lifecycle, Scalar |
| `order-service` | `deploy/OrderService.Sample.Dockerfile` | Sample consumer — 10 `[RequirePermission]` endpoints, registers at startup |
| `vault` | `hashicorp/vault:1.20` | Signing-key material source of truth |
| `redis` | `redis:7-alpine` | Key rotation lock |

## 1. Prerequisites

- Docker Engine + compose plugin
- 4 GB free RAM (two Oracle XE instances are the bulk of it)
- Host ports **5080, 8080, 5180, 8200, 1521** free — or override with
  `FACADE_HTTP_PORT`, `KEYCLOAK_HTTP_PORT`, `ORDER_HTTP_PORT` (Oracle ports fixed at 1521; the two
  DBs share it on different service names, reachable only inside the compose network except 1521)

## 2. Start the stack

```bash
cd deploy
docker compose up --build -d
docker compose ps
```

Wait for all seven services to show `healthy` (Oracle takes 1–2 min on first boot):

```bash
watch docker compose ps
```

Startup order is enforced by healthchecks:
`keycloak-db` / `identity-meta-db` → `keycloak` → `identity-facade` → `order-service`.

## 3. Verify health

```bash
curl -fsS http://localhost:5080/health/live          # facade
curl -fsS http://localhost:8080/health/ready -o /dev/null -w "%{http_code}\n"   # keycloak (host)
curl -fsS http://localhost:5180/health/live          # order-service sample
```

`200` everywhere = good. If Keycloak reports unhealthy, check
`docker compose logs keycloak | tail -50` — the most common cause is the realm import (below).

## 4. Log in and get a token — through the facade only

All tokens are genuine Keycloak-issued JWTs, obtained through the facade's login proxy
(the facade never mints tokens; it forwards the grant as received):

```bash
TOKEN=$(curl -s -X POST http://localhost:5080/api/identity/auth/login \
  -d "grant_type=password&client_id=identity-facade&client_secret=facade-development-only&username=admin&password=admin" \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['access_token'])")
echo "$TOKEN" | cut -c1-40   # peek, never log the whole token
```

Machine clients use the same endpoint with a client-credentials grant:

```bash
curl -s -X POST http://localhost:5080/api/identity/auth/login \
  -d "grant_type=client_credentials&client_id=order-service&client_secret=order-service-development-only"
```

## 5. Call the Identity Facade (Scalar at /scalar)

Open **http://localhost:5080/scalar** — 39 endpoints across Auth / Users / Roles / Permissions / Business Roles / Scoped Access / Access / Keys (Admin). Click **Authenticate → Bearer**, paste `$TOKEN`, and "Try it":

```bash
curl -s http://localhost:5080/api/identity/me -H "Authorization: Bearer $TOKEN"
curl -s "http://localhost:5080/api/identity/users?page=1&pageSize=5" -H "Authorization: Bearer $TOKEN"
curl -s "http://localhost:5080/api/identity/roles?page=1&pageSize=10" -H "Authorization: Bearer $TOKEN"
curl -s "http://localhost:5080/api/identity/permissions?serviceId=order-service" -H "Authorization: Bearer $TOKEN"
```

`/me` returns the caller's id/username/roles/permissions. The `admin` user carries all
`Identity.*` permissions; other users get only what their realm roles map into the
`permissions` claim.

## 6. Watch the sample register its permissions

On first start, `order-service` discovers its ten `[RequirePermission]` actions and pushes a
manifest to the facade, which mirrors them as Keycloak realm roles
(`Orders.View`, `Orders.Create`, … `Orders.Reports.Export`):

```bash
docker compose logs order-service | grep -i registered
# expect: Permission manifest registered for order-service v1.0.0 (10 permissions, attempt 1)

curl -s "http://localhost:5080/api/identity/permissions?serviceId=order-service" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

Registration is retried with exponential backoff and never blocks the sample's startup.

## 7. Call the sample service (Scalar at /scalar on 5180)

The sample never contacts Keycloak: it validates tokens against the facade's
`/.well-known/openid-configuration` + `/api/identity/oidc/jwks` proxy
(`AcceptIssuerFromDiscovery`). A token is honored if it carries the required
`Orders.*` permission claim.

Grant `admin` the `Orders.View` role once (Keycloak Admin Console → company realm →
Users → admin → Role mapping → add `Orders.View`), or via Admin REST, then:

```bash
curl -s http://localhost:5180/api/orders -H "Authorization: Bearer $TOKEN"
# [{"id":"ord-1","customerUsername":"admin","total":120.50,"status":"open"}, ...]
```

Without the permission the call returns 403; without a token, 401.
Browse **http://localhost:5180/scalar** for all ten guarded endpoints.

### Business roles & scoped access

> The full target flow below (login → create role → assign permissions → create scoped
> user → verify token claims) is scripted end-to-end in **`deploy/smoke-test.sh`** — run
> it after `docker compose up` to verify everything at once.

```bash
# Create a composite business role (permissions are client roles registered by order-service)
curl -s -X POST http://localhost:5080/api/identity/business-roles \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"RegionalManager","permissions":["Orders.View","Orders.Create"]}' | python3 -m json.tool

# Create a user with scoped assignment (region/branch are arbitrary keys)
curl -s -X POST http://localhost:5080/api/identity/users \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"username":"alice","email":"alice@example.com","enabled":true,"credentials":{"password":"Secret123!","temporary":false},"assignments":[{"role":"RegionalManager","scopes":{"region":["tehran-1"]}}]}' | python3 -m json.tool

# Read back effective authorization (authoritative) — also available as flat JWT claims authz.scope.<key>
curl -s http://localhost:5080/api/identity/access-context -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
# Inspect the token itself (flat per-scope claims, plus legacy iam_access kept during migration)
echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool | grep -E "authz\.scope|iam_access|permissions"

# Add a new scope value without touching DTOs — arbitrary keys via the registry (backed by Keycloak group /iam-scope-registry)
curl -s http://localhost:5080/api/identity/scopes -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
# Assign test-key to a user: both scalar and array forms normalize ("test-key": "items-1"  ==  "test-key": ["items-1"])
curl -s -X PUT http://localhost:5080/api/identity/users/<userId>/scoped-access \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"assignments":[{"role":"RegionalManager","scopes":{"test-key":"items-1"}}]}' | python3 -m json.tool
# Re-login (or refresh) — new JWT now carries "authz.scope.test-key": ["items-1"] via the authz-scopes clientScope

# New service permission appears on Admin without re-login / without Keycloak console:
# after the service registers its manifest, reconcile any missing mappings:
curl -s -X POST http://localhost:5080/api/identity/permissions/reconcile-admin -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
# then POST /api/identity/auth/refresh with the refresh_token — new access token already has the permission
```

Consumer services read scopes via `ICurrentAccessContext.GetScopeValues("region")` / `HasPermission(..., "region", value)` — see `samples/OrderService.Sample/Program.cs` (`/api/orders/scoped`, `/api/orders/{id}/scoped-check`). `EnsureLoadedAsync()` resolves via the facade when the claim was omitted for size. The scope system is **Keycloak-attribute-driven** (`authz.scope.<key>` multivalued on user/group + registry group `/iam-scope-registry` holding `scope.<key>`/`resource.<name>`); it accepts both `"test-key": "items-1"` (scalar, normalized by `ScopeDictionaryConverter`) and `"test-key": ["items-1"]`; unknown/inactive/disallowed scopes return `400 ValidationProblem` with `assignments[0].scopes.<key>` errors. Filtering in consumers uses `ScopeFilterService.ApplyAsync` (see `samples/OrderService.Sample/ScopeFilters.cs`) — deny-by-default, per-`IScopeFilterHandler` (no raw SQL), resource isolation enforced (e.g. `test-key` only on `ResourceA`). The declarative User Profile hardens `authz.scope.*` to `admin`-only (`PUT /admin/realms/{realm}/users/profile`).

## 8. What lives where (config ownership)

- **Identity Facade config** (`src/Identity.Api/appsettings.json` + compose env):
  `Identity:Keycloak:BaseUrl`, `Identity:KeycloakAdmin:*`, `Identity:Authority`.
  This is the ONLY place that knows Keycloak's address.
- **Sample/consumer config** (`samples/OrderService.Sample/appsettings.json`):
  only `Identity:Authority` (points at the facade), `Identity:Audience`,
  `PermissionRegistration:IdentityServer`, `ClientId`, `ClientSecret`.
  No Keycloak URL, realm, or admin secret anywhere in the consumer.
- **Realm definition** (`deploy/realm-company.json`): clients `identity-facade`
  (secret `facade-development-only`) and `order-service`
  (secret `order-service-development-only`), the permission claim mappers
  (`permissions`/`permission` from realm roles, `aud: identity-facade`,
  `sub`, `preferred_username`), realm roles `Identity.*`/`identity.*`, the groups
  `super-admins` (always-present unrestricted admin — every registered client role is
  auto-mapped to it, plus the `identity.*` facade-management permissions), `key-admins`,
  `iam-scope-registry`, and the `admin` user (member of `super-admins` + `key-admins`).

## 9. Re-importing the realm after changes

`deploy/realm-company.json` is imported once (IGNORE_EXISTING). After editing it:

```bash
AT=$(curl -s -X POST http://localhost:8080/realms/master/protocol/openid-connect/token \
  -d "grant_type=password&client_id=admin-cli&username=admin&password=admin-development-only" \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['access_token'])")
curl -X DELETE http://localhost:8080/admin/realms/company -H "Authorization: Bearer $AT"
docker compose restart keycloak      # re-imports the realm on boot
docker compose restart identity-facade order-service   # clear their cached discovery docs
```

## 10. Teardown

```bash
cd deploy
docker compose down          # keep data volumes
docker compose down -v       # also wipe Oracle/Redis data
```

## Troubleshooting

| Symptom | Cause / fix |
| --- | --- |
| Keycloak `unhealthy`, no curl errors in log | Fixed healthcheck probes port 9000 via `/dev/tcp`; ensure compose file is current |
| Vault `unhealthy` | Its healthcheck forces `VAULT_ADDR=http://…` — dev server is plain HTTP |
| `invalid_grant` on login | Password wrong or brute-force lockout; clear via Admin REST `attack-detection` or re-import realm |
| `unauthorized_client` on client_credentials | Client secret mismatch; ensure `client.secret.creation.time: "0"` attribute is in the realm JSON so the import keeps the declared secret |
| Token has no `aud`/`sub`/`permissions` | Realm JSON mappers missing — re-import the realm |
| 401 from a consumer with a valid token | Consumer cached an old discovery doc — restart it; `jwks_uri` is served relative to the caller's Host |
| Port already allocated | Override `FACADE_HTTP_PORT` / `KEYCLOAK_HTTP_PORT` / `ORDER_HTTP_PORT` |
| Facade 401 after realm re-import | Facade cached the previous realm signing key — `docker compose restart identity-facade` |
