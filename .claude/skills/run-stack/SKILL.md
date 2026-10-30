---
name: run-stack
description: Start, verify and stop the Identity Gateway stack (Aspire AppHost with PostgreSQL, Keycloak, Redis, gateway, sample). Use when asked to run the app, check that a runtime change works, or run the smoke test.
---

# Run the Identity Gateway stack

## Start
0. A running stack locks the DLLs in `bin/`: always stop it (see below) before `dotnet build`.
1. Make sure Docker is running: `docker version --format '{{.Server.Version}}'`.
2. Build first so the run can use `--no-build`: `dotnet build IdentityService.slnx`.
3. Start the AppHost **in the background**, logging to the scratchpad:
   `dotnet run --project src/Identity.AppHost --launch-profile http --no-build > <scratchpad>/apphost.log 2>&1`
4. Wait (background `until` loop, 1 s polling, ~5 min cap, `curl -m 3`) until:
   - gateway `http://localhost:5080/health` answers `Healthy` (Keycloak bootstrap done for every tenant)
   - console `http://localhost:5090/alive` answers 200
   - sample  `http://localhost:5081/health/live` answers 200
   Also break out of the loop on `fail:|Unhandled exception|Distributed application failed` in the log.
   The first run pulls images and takes a few minutes; later runs take about 15 s.

Endpoints: Aspire dashboard `http://localhost:15140` (login URL with token is in the log),
Keycloak `https://localhost:18080` (dev certificate), gateway `http://localhost:5080`,
admin console `http://localhost:5090`, sample `http://localhost:5081`.
Tenants: `company` (default) and the demo tenant `acme` (header `X-Tenant-Id: acme`); dev login `admin`/`admin` in both.

If a project exits right after start, run its DLL directly (`dotnet bin/Debug/net10.0/<Project>.dll`) to see the
startup exception; a stale static-web-assets manifest is fixed with `dotnet build --no-incremental`.

## Verify
- `IDENTITY_E2E=1 dotnet test tests/Identity.E2E.Tests` starts its own stack (stop the dev stack first).
- `bash scripts/smoke-test.sh` runs the business flow: login, create role, assign permission,
  create scoped user, check token claims and access-context. All 7 steps must pass.
- Login through the gateway is form-encoded (`grant_type=password&client_id=...`), not JSON.
- Discovery through the gateway: `curl http://localhost:5080/.well-known/openid-configuration`.

## Stop and clean up
1. Stop the background task (TaskStop).
2. Killing the process orphans the session containers and the project processes. Remove them:
   `docker ps --format '{{.Names}}' | grep -E '^(keycloak|redis)-' | xargs -r docker rm -f`
   `powershell -NoProfile -Command "Get-Process Identity.Gateway,Identity.Admin,OrderService.Sample,Identity.AppHost -ErrorAction SilentlyContinue | Stop-Process -Force"`
3. Leave `postgres-*` running; it is a persistent container holding the Keycloak database.
   Smoke-test data (roles `smoke-accountant-*`, users `smoke-user-*`) stays in that database.

## Troubleshooting
- `SSL connection could not be established` / Apache 404 on a Keycloak URL: something else owns
  the port. Port 8080 is a local Apache on the owner's machine, which is why Keycloak uses 18080.
- Admin password: generated Aspire parameter `keycloak-admin-password`, stored in the AppHost
  user secrets (`dotnet user-secrets list --project src/Identity.AppHost`).
