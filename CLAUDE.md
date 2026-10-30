# Identity Gateway — agent guide

## Role
Senior .NET solution architect: ASP.NET Core (.NET 10), Clean Architecture, .NET Aspire 13,
Keycloak 26.4 (Admin REST API, realms, clients, groups, roles, mappers, flows, user federation),
Redis, Radzen Blazor.

## What this repository is
**Identity Gateway**: a stateless .NET gateway over Keycloak. It hides Keycloak from end users and
admins while exposing most of its features: authentication on behalf of users and services,
applications/modules, permissions, business roles, users, runtime scopes, weekly access schedules
and auth settings, plus a Persian (RTL) admin console.

Consumer services use the `Avash.Identity.*` packages (authentication, authorization,
access context, permission discovery/registration).

## Binding architecture decisions (owner, 2026-10-30)
- **Keycloak is the only data store.** The gateway owns no database. Everything (applications,
  permissions, roles, scopes, schedules, settings) is stored as Keycloak entities and attributes.
  Redis is a cache only. Do not add EF Core, SQLite or any gateway-owned DB.
- Signing keys are managed inside Keycloak. There is no key-management module and no Vault.
- Keycloak's database is **PostgreSQL**.
- Local orchestration is **.NET Aspire** (`src/Identity.AppHost`). There is no docker-compose.
- Admin UI: **Radzen Blazor**, Persian RTL. Build each feature's page in the same phase as its API.
- Multi-tenant enterprise target: **one Keycloak realm per tenant (organization)**; very large
  tenants may get a dedicated Keycloak cluster. Design every Keycloak call to be tenant (realm) aware.
- Auth types to support: direct login via gateway APIs, SSO with a per-application login page
  (`login_theme` client attribute), LDAP/Active Directory (user federation), OTP/MFA.
  SMS login is **deferred** until the owner asks for it.

## Keycloak storage model (target)
| Concept | Keycloak entity |
|---|---|
| Tenant | Realm |
| Application | Client; display metadata in client attributes; per-app login page via `login_theme` |
| Permission | Client role named `Module:Resource:Action`; emitted as `App:Module:Resource:Action`. Source (manual/synced) and deprecation live in role attributes. The admin UI builds a tree with "check all" per level from these segments, plus "all Read of an app" |
| Business role | Group. Permissions = client-role mappings. Attributes: display name, required scope keys (e.g. province+city required, district optional), schedule |
| Scope keys | Attributes of the `iam-scope-registry` group (owner's existing model; keep it) |
| User scope values | User attributes `authz.scope.<key>`; role scope requirements are enforced on user create/assign |
| Weekly schedule | `access.schedule` attribute on realm (default), group (role), client role (permission) or user (override, e.g. `unrestricted` for remote workers). Precedence: user > permission > role > realm |
| Audit | Keycloak admin events + login events |
| Auth settings | Realm settings, authentication flows, OTP/password policies, identity providers, LDAP components |

The super-admin group `super-admins` must always exist and hold every permission.
Delegated admins may only manage users inside their own scope and grant only what they hold.

## Layout
| Path | Purpose |
|---|---|
| `src/Identity.AppHost` | Aspire AppHost: PostgreSQL, Keycloak (realms `company` + demo tenant `acme` from `Keycloak/Realms`, Persian `avash` login theme from `Keycloak/Themes`), Redis, gateway, console, sample |
| `src/Identity.ServiceDefaults` | OpenTelemetry, health, service discovery, resilience (no retries for unsafe methods) |
| `src/Identity.Gateway` | Host: minimal API endpoints, error model, tenancy (`Tenancy/`), Keycloak bootstrap (`Bootstrap/`) |
| `src/Identity.Admin` | Persian RTL admin console (Radzen Blazor, interactive server, OIDC code + PKCE per tenant) |
| `src/Identity.Application` / `Identity.Domain` / `Identity.Contracts` | Use cases, domain, DTOs |
| `src/Identity.Infrastructure.Keycloak` / `.Redis` / `Identity.Infrastructure` | Adapters |
| `src/Avash.Identity.*` | Consumer packages |
| `samples/OrderService.Sample` | Sample consumer service |
| `tools/Identity.TenantProvisioning` | Operator tool: creates a new tenant realm with master credentials (the gateway never gets them) |
| `scripts/smoke-test.sh` | Business-flow smoke test against a running stack |
| `tests/Identity.E2E.Tests` | End-to-end tests that start the stack with `Aspire.Hosting.Testing` (only with `IDENTITY_E2E=1`) |
| `docs/` | Persian docs: architecture + Keycloak ERD, run guide, API summary |

## Commands
```bash
dotnet build IdentityService.slnx            # TreatWarningsAsErrors is on
dotnet test IdentityService.slnx
dotnet run --project src/Identity.AppHost --launch-profile http   # whole stack + Aspire dashboard
bash scripts/smoke-test.sh                   # needs the stack running
IDENTITY_E2E=1 dotnet test tests/Identity.E2E.Tests   # starts its own stack; dev stack must be stopped
```
Use the `run-stack` skill to start, verify and stop the stack correctly.

## Working agreement with the owner
- **Talk to the owner in Persian.** Code, identifiers, comments, commits and PR text are English.
- Go **step by step**. Any architectural or breaking change: stop and ask in Persian first.
- **Every change ships as its own MR/PR and waits for the owner's approval** before the next step.
  Follow Git flow (see the `git-flow-mr` skill).
- Small, verifiable changes; build and test after each one; run the stack for runtime changes.
- Report outcomes honestly, including failing tests or skipped verification.

## Engineering rules
- No secrets in code or committed config for non-dev use; use Aspire parameters / configuration.
- Do not invent Keycloak endpoints or representation fields; verify against Keycloak **26.4**
  Admin REST API docs before use.
- Never swallow exceptions (`catch {}`); surface Keycloak failures as ProblemDetails with a
  correlation id, without leaking raw Keycloak bodies.
- Keycloak Admin API writes are not idempotent: no blind retries on POST/PUT/DELETE.
- Keep the Domain free of infrastructure; endpoints call application use cases, not adapters.
- Persian Markdown docs follow the global RTL rules (RLM after markers, manual TOC, no dir wrappers).

## Environment gotchas
- Port 8080 is taken by a local Apache on the owner's machine; Keycloak runs on **18080**,
  and Aspire serves it over HTTPS with the dev certificate.
- Stopping the AppHost by killing its process orphans session containers (`keycloak-*`, `redis-*`);
  remove them. The `postgres-*` container is persistent on purpose.
- VS Code's C# language server locks `bin/obj`; move tracked files with per-file `git mv`
  instead of renaming whole directories.
- Remote is GitHub (`origin`, SSH). `gh` may be unauthenticated: push the branch and give the
  owner the compare link, or ask them to run `gh auth login`. GitHub's default base is `master`;
  PRs must target `develop`.
- After stashing/unstashing source files, rebuild with `--no-incremental`; otherwise tests can run
  against stale binaries. The same after deleting a `wwwroot` (stale static-web-assets manifest crashes startup).
- `dotnet test` does not rebuild the AppHost; run `dotnet build IdentityService.slnx` before starting the stack.
- Keycloak imports a realm only when it does not exist yet: a realm imported with missing secrets must be
  deleted (master admin) and the stack restarted.
- Tenant realms define their own client scopes, so Keycloak's built-in `profile`/`basic` scopes do not exist;
  clients carry their own `sub`/`preferred_username` mappers.

## Known open issues
- Weekly schedules are not enforced on Keycloak's own login page (only gateway login/refresh and
  consumers); a Keycloak authenticator SPI is a follow-up.
- The console keeps tokens in server memory: a console restart signs administrators out.

## Roadmap
1. Foundation: cleanup, rename, Aspire, agent knowledge (done)
2. Security hotfixes (done)
3. Keycloak core: tenant-aware admin client, Result + ProblemDetails error model (done)
4. Applications and permissions: `App:Module:Resource:Action`, persistent catalog and sync (done)
5. Roles and scopes: required scope keys, value hierarchy and catalog, delegated admin (done)
6. Users: lockout, credentials/OTP reset, required actions, delegated visibility (done)
7. Weekly schedules: attributes, API, gateway login/refresh and consumer enforcement (done; login SPI open)
8. Auth settings: tokens, password policy, brute force, OTP/MFA, IdPs, LDAP/AD, Persian login theme (done)
9. Multi-tenancy: realm per tenant, tenant header, per-issuer token validation, provisioning tool (done)
10. Radzen admin console and E2E tests with `Aspire.Hosting.Testing` (done)
11. Documentation in Persian (done)
12. Next: Keycloak schedule SPI (approved 2026-10-31), SMS login (when the owner asks)
