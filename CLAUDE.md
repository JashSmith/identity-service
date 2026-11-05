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

Consumer services use the `Avash.Identity.*` packages (bearer authentication for APIs, `AddAvashWebSso` +
`MapAvashSso` for server-rendered web apps/BFFs with single sign-on and back-channel logout, authorization,
access context, permission discovery/registration).

## Binding architecture decisions (owner, 2026-10-30)
- **Keycloak is the only data store.** The gateway owns no database. Everything (applications,
  permissions, roles, scopes, schedules, settings) is stored as Keycloak entities and attributes.
  Redis is a cache only. Do not add EF Core, SQLite or any gateway-owned DB.
- Signing keys are managed inside Keycloak. There is no key-management module and no Vault.
- Keycloak's database is **PostgreSQL**.
- Local orchestration is **.NET Aspire** (`src/Hosts/Identity.AppHost`). There is no docker-compose.
- Admin UI: **Radzen Blazor**, Persian RTL. Build each feature's page in the same phase as its API.
- Multi-tenant enterprise target: **one Keycloak realm per tenant (organization)**; very large
  tenants may get a dedicated Keycloak cluster. Design every Keycloak call to be tenant (realm) aware.
- Auth types to support: direct login via gateway APIs, SSO with a per-application login page
  (`login_theme` client attribute), LDAP/Active Directory (user federation), OTP/MFA.
  SMS sign-in (owner, 2026-11-05): per tenant `off`, `passwordless` (mobile number + code) or `second-factor`
  (password + code), on Keycloak's login page and in the gateway login API. Keycloak's Avash authenticators make and
  check the codes; they call the gateway (HMAC-signed) to deliver them through the tenant's SMS provider.

## Keycloak storage model (target)
| Concept | Keycloak entity |
|---|---|
| Tenant | Realm |
| Application | Client; display metadata in client attributes. Login page mode in `iam.login.mode`: `inherit` (realm theme), `branded` (`login_theme=avash` + `iam.login.{title,subtitle,logo_url,primary_color,background}`, rendered by `keycloak/themes/avash/login/footer.ftl`), `theme` (any installed theme in `login_theme`), `embedded` (app's own form via the direct login API; only this mode enables `directAccessGrantsEnabled`) |
| Permission | Client role named `Module:Resource:Action`; emitted as `App:Module:Resource:Action`. Source (manual/synced) and deprecation live in role attributes. The admin UI builds a tree with "check all" per level from these segments, plus "all Read of an app" |
| Business role | Group. Permissions = client-role mappings. Attributes: display name, required scope keys (e.g. province+city required, district optional), schedule |
| Scope keys | Attributes of the `iam-scope-registry` group (owner's existing model; keep it) |
| User scope values | User attributes `authz.scope.<key>`; role scope requirements are enforced on user create/assign |
| Weekly schedule | `access.schedule` attribute on realm (default), group (role), client role (permission) or user (override, e.g. `unrestricted` for remote workers). Precedence: user > permission > role > realm |
| Audit | Keycloak admin events + login events |
| Auth settings | Realm settings, authentication flows, OTP/password policies, identity providers, LDAP components |
| SMS settings | Realm attributes `iam.sms.enabled`, `iam.sms.provider`, `iam.sms.<provider>.<field>`. Keycloak replaces the whole attribute map on a realm PUT: always read, merge, write the full map |
| SMS sign-in | Realm attributes `iam.smslogin.{mode,code_length,ttl_seconds,resend_seconds,max_attempts}` (read by the Keycloak authenticators). User mobile number: attribute `phone_number` (+989..., unique, admin-only, set only via `PhoneNumber`). Flows: `avash-browser` gets `avash-sms-otp` in its forms sub-flow and the alternative sub-flow `avash-browser sms`; `avash-direct-grant` (built by the gateway) is bound only while SMS sign-in is on. The gateway only toggles requirements after adding the steps once |

The super-admin group `super-admins` must always exist and hold every permission.
Delegated admins may only manage users inside their own scope and grant only what they hold.

## Layout
| Path | Purpose |
|---|---|
| `src/Hosts/Identity.AppHost` | Aspire AppHost: PostgreSQL, Keycloak (realms, themes and providers from `keycloak/`), Redis, gateway, console |
| `src/Hosts/Identity.ServiceDefaults` | OpenTelemetry, health, service discovery, resilience (no retries for unsafe methods) |
| `src/Hosts/Identity.Gateway` | Host: minimal API endpoints, error model, tenancy (`Tenancy/`), Keycloak bootstrap (`Bootstrap/`) |
| `src/Hosts/Identity.Admin` | Persian RTL admin console (Radzen Blazor, interactive server, OIDC code + PKCE per tenant) |
| `src/Core/Identity.Application` / `Identity.Domain` / `Identity.Contracts` | Use cases, domain, DTOs |
| `src/Infrastructure/Identity.Infrastructure.Keycloak` / `.Redis` / `.Sms` / `Identity.Infrastructure` | Adapters (`.Sms`: SMS providers; add one with `AddSmsProvider<T>()`) |
| `src/Packages/Avash.Identity.*` | Consumer packages |
| `tools/Identity.TenantProvisioning` | Operator tool: creates a new tenant realm with master credentials (the gateway never gets them) |
| `keycloak/realms` | Realm imports: `company` and the demo tenant `acme` (imported only when the realm does not exist) |
| `keycloak/themes` | Keycloak themes mounted into the container (Persian `avash` login theme) |
| `keycloak/extensions` | Java Keycloak extensions (weekly-schedule authenticator; SMS sign-in authenticators with their login templates and messages in `theme-resources`), built and unit-tested in Docker by `scripts/build-keycloak-extensions.sh` into `keycloak/providers` |
| `scripts/smoke-test.sh` | Business-flow smoke test against a running stack |
| `tests/Identity.Admin.Tests` | bUnit tests of the console (design-system components, menu permissions, Persian formatting) |
| `tests/Identity.Packages.Tests` | Consumer-package tests (permission discovery, manifests, scope filters) against a test-only fixture |
| `tests/Identity.E2E.Tests` | End-to-end tests that start the stack with `Aspire.Hosting.Testing` on the fixed dev ports (only with `IDENTITY_E2E=1`); `ConsumerHost` is an in-process consumer service; `Ui/` drives the console in the installed Chrome with Playwright and fails on any HTTP >= 400 or browser console error |
| `docs/` | Persian docs: index (`docs/README.md`), integration guide, per-app login pages, console guide, architecture, run guide, API summary; screenshots in `docs/images`. Check/fix the RTL rules with `python scripts/check-docs.py --fix` |

## Commands
```bash
dotnet build IdentityService.slnx            # TreatWarningsAsErrors is on
dotnet test IdentityService.slnx
dotnet run --project src/Hosts/Identity.AppHost --launch-profile http   # whole stack + Aspire dashboard
bash scripts/smoke-test.sh                   # needs the stack running
IDENTITY_E2E=1 dotnet test tests/Identity.E2E.Tests   # starts its own stack; dev stack must be stopped
IDENTITY_E2E=1 dotnet test tests/Identity.E2E.Tests --filter "FullyQualifiedName~Ui"   # browser tests only (PLAYWRIGHT_HEADED=1 shows the browser)
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
- Console design system: colours only through the `--av-*` tokens in `wwwroot/css/theme.css` (never hard-coded),
  layout in `wwwroot/app.css`, shared components in `Components/Shared` (`PageHeader`, `StatCard`, `EmptyState`,
  `ThemeSwitch`, `Girih`). Fonts (Vazirmatn, Vazir Code) are self-hosted. No `letter-spacing` or `uppercase` on
  Persian text. Numbers and dates shown to users go through `PersianFormat` (Persian digits, Jalali, Tehran time).
  After upgrading Radzen.Blazor rerun `python scripts/generate-radzen-dark-css.py`.

## Environment gotchas
- Keycloak reaches the gateway at `AVASH_GATEWAY_URL` (Aspire resolves it, `aspire.dev.internal`); the HMAC secret is the
  generated Aspire parameter `sms-hook-secret` (`AVASH_SMS_HOOK_SECRET` / `Identity__SmsLogin__HookSecret`).
- Two failed sign-ins of one user within a second lock it for 60 s (Keycloak's quick-login check), also in tests.
  In `second-factor` mode the admin needs a code too: tests take the admin token first and always switch back to `off`.
- Port 8080 is taken by a local Apache on the owner's machine; Keycloak runs on **18080**,
  and Aspire serves it over HTTPS with the dev certificate.
- Browsers send a host's cookies to every port of it: on `localhost` the console's and apps' cookies reach Keycloak too.
  Keep auth cookies small (server-side ticket store, `DistributedCacheTicketStore`); Keycloak answers 431 past ~8 KB.
- Docker Desktop on the owner's machine can leak thousands of half-closed connections (port 8888, `gost-proxy`),
  exhausting Windows ephemeral ports: `WSAENOBUFS`, `ERR_NO_BUFFER_SPACE`, `ERR_ADDRESS_IN_USE`. Check with
  `netstat -ano`; the owner decides on restarting Docker Desktop.
- The AppHost refuses to start when ports 5080/5090/18080 are taken (`PortPreflight`): never run the dev stack and the
  E2E tests at the same time; without the check Aspire's DCP only failed after a 2-minute `TimeoutRejectedException`.
- Stopping the AppHost by killing its process orphans session containers (`keycloak-*`, `redis-*`);
  remove them. The `identity-postgres` container (volume `identity-postgres-data`) is persistent on purpose;
  its name is pinned in the AppHost because Aspire's default names hash the AppHost path.
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
- An SSO session opened inside the schedule is not re-checked when it signs in to another application
  (cookie path); it ends with the SSO idle timeout.
- `super-admins` members follow the realm's default schedule; give them an `unrestricted` user override.
- The console keeps tokens and the auth ticket in server memory: a console restart signs administrators out.

## Roadmap
1. Foundation: cleanup, rename, Aspire, agent knowledge (done)
2. Security hotfixes (done)
3. Keycloak core: tenant-aware admin client, Result + ProblemDetails error model (done)
4. Applications and permissions: `App:Module:Resource:Action`, persistent catalog and sync (done)
5. Roles and scopes: required scope keys, value hierarchy and catalog, delegated admin (done)
6. Users: lockout, credentials/OTP reset, required actions, delegated visibility (done)
7. Weekly schedules: attributes, API, gateway login/refresh, consumer enforcement and Keycloak authenticator (done)
8. Auth settings: tokens, password policy, brute force, OTP/MFA, IdPs, LDAP/AD, Persian login theme (done)
9. Multi-tenancy: realm per tenant, tenant header, per-issuer token validation, provisioning tool (done)
10. Radzen admin console and E2E tests with `Aspire.Hosting.Testing` (done)
11. Documentation in Persian (done)
12. Console redesign, dashboard and audit, per-app login pages, web SSO package, SMS provider infrastructure (done)
13. SMS sign-in: passwordless and second factor, login page and API, user mobile numbers (done)

## graphify

This project has a knowledge graph at graphify-out/ with god nodes, community structure, and cross-file relationships.

Rules:
- When graphify-out/graph.json exists, run `graphify query "<question>"` before your first grep, search or source-file read for a codebase question, and put this rule in every subagent prompt that explores code. Read raw files only for lines the graph or an earlier read already located. Use `graphify path "<A>" "<B>"` for relationships and `graphify explain "<concept>"` for focused concepts. These return a scoped subgraph, usually much smaller than GRAPH_REPORT.md or raw grep output.
- If graphify-out/wiki/index.md exists, use it for broad navigation instead of raw source browsing.
- Read graphify-out/GRAPH_REPORT.md only for broad architecture review or when query/path/explain do not surface enough context.
- After modifying code, run `graphify update .` to keep the graph current (AST-only, no API cost).
- A committed graphify-out/graph.json is rewritten whole on every build, so a large diff to it in a pull request is expected. Do not flag it as churn or suggest skipping the graph rebuild or its hooks.
