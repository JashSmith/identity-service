// Local orchestration for the Identity Gateway stack:
// PostgreSQL (Keycloak's database) -> Keycloak -> Identity Gateway -> admin console, plus Redis as cache.
// The gateway keeps no database of its own; Keycloak is the single source of truth.

const string KeycloakRealm = "avash";
const string KeycloakImageTag = "26.4";
// Fixed so the token issuer stays stable across runs; 8080 is avoided because it is
// commonly taken by other local web servers.
const int KeycloakPort = 18080;

// Before anything creates an HttpClient: with a Windows system proxy that does not bypass local addresses, the
// AppHost's calls to Aspire's orchestrator on localhost would go to the proxy and time out after two minutes.
Identity.ServiceDefaults.LoopbackProxyBypass.Install();

var builder = DistributedApplication.CreateBuilder(args);

// Explicit names: Aspire's defaults hash the AppHost's path, so moving the project would silently start
// Keycloak on an empty database.
var postgres = builder.AddPostgres("postgres")
    .WithContainerName("identity-postgres")
    .WithDataVolume("identity-postgres-data")
    .WithLifetime(ContainerLifetime.Persistent);
var keycloakDb = postgres.AddDatabase("keycloak-db", databaseName: "keycloak");

var redis = builder.AddRedis("redis")
    .WithDataVolume("identity-redis-data");

// Bootstrap admin of the master realm. The password is generated once and persisted
// in the AppHost user secrets; it is never hardcoded.
var keycloakAdmin = builder.AddParameter("keycloak-admin", "admin");
var keycloakAdminPassword = builder.AddParameter(
    "keycloak-admin-password",
    new GenerateParameterDefault { MinLength = 24, Special = false },
    secret: true,
    persist: true);

// Confidential client secrets: generated once, persisted in the AppHost user secrets and injected
// into the realm import through ${...} placeholders, so no secret lives in the repository.
var gatewayClientSecret = ClientSecret("gateway-client-secret");
var gatewayAdminClientSecret = ClientSecret("gateway-admin-client-secret");
// The admin console's OIDC client; the gateway creates it in every tenant realm with this secret.
var adminConsoleClientSecret = ClientSecret("admin-console-client-secret");
// Shared by Keycloak's Avash SMS authenticators and the gateway: signs the "send this SMS code" calls.
var smsHookSecret = ClientSecret("sms-hook-secret");
const string AdminConsoleUrl = "http://localhost:5090";

var keycloak = builder.AddKeycloak("keycloak", port: KeycloakPort, keycloakAdmin, keycloakAdminPassword)
    .WithImageTag(KeycloakImageTag)
    .WithRealmImport(KeycloakAssets("realms"))
    // Custom themes (e.g. "avash": Persian RTL login); Keycloak's built-in themes live in its jars, not in this folder.
    .WithBindMount(KeycloakAssets("themes"), "/opt/keycloak/themes", isReadOnly: true)
    // Extensions built by scripts/build-keycloak-extensions.sh (e.g. the weekly-schedule authenticator).
    .WithBindMount(KeycloakAssets("providers"), "/opt/keycloak/providers", isReadOnly: true)
    .WithEnvironment("KC_DB", "postgres")
    .WithEnvironment("KC_DB_URL", ReferenceExpression.Create(
        $"jdbc:postgresql://{postgres.Resource.PrimaryEndpoint.Property(EndpointProperty.HostAndPort)}/{keycloakDb.Resource.DatabaseName}"))
    .WithEnvironment("KC_DB_USERNAME", postgres.Resource.UserNameReference)
    .WithEnvironment("KC_DB_PASSWORD", postgres.Resource.PasswordParameter)
    // Browsers reach Keycloak over HTTPS, hence HTTP/2, where Quarkus caps the whole header list at 8192 bytes
    // (quarkus.http.limits.max-header-list-size) and answers 431. A browser sends every localhost cookie of every port
    // (Aspire dashboard, console, demo apps, other local projects) to Keycloak too, so the cap is reached in development
    // even though each of our cookies is small. 32 KB matches Kestrel's limit for the other services; HTTP/1.1 is not affected.
    .WithEnvironment("QUARKUS_HTTP_LIMITS_MAX_HEADER_LIST_SIZE", "32768")
    .WithEnvironment("GATEWAY_CLIENT_SECRET", gatewayClientSecret)
    .WithEnvironment("GATEWAY_ADMIN_CLIENT_SECRET", gatewayAdminClientSecret)
    .WithEnvironment("AVASH_SMS_HOOK_SECRET", smsHookSecret)
    .WaitFor(keycloakDb);

var keycloakHttp = keycloak.GetEndpoint("http");

var gateway = builder.AddProject<Projects.Identity_Gateway>("identity-gateway")
    .WithEnvironment("Identity__Authority", ReferenceExpression.Create($"{keycloakHttp}/realms/{KeycloakRealm}"))
    .WithEnvironment("Identity__Keycloak__BaseUrl", keycloakHttp)
    .WithEnvironment("Identity__Keycloak__Realm", KeycloakRealm)
    .WithEnvironment("Identity__Keycloak__ClientSecret", gatewayClientSecret)
    .WithEnvironment("Identity__KeycloakAdmin__BaseUrl", keycloakHttp)
    .WithEnvironment("Identity__KeycloakAdmin__Realm", KeycloakRealm)
    // The gateway uses its own service account in the tenant realm, never the master superuser.
    .WithEnvironment("Identity__KeycloakAdmin__AdminClientId", "identity-gateway-admin")
    .WithEnvironment("Identity__KeycloakAdmin__AdminClientSecret", gatewayAdminClientSecret)
    .WithEnvironment("Identity__AdminConsole__BaseUrl", AdminConsoleUrl)
    .WithEnvironment("Identity__AdminConsole__ClientSecret", adminConsoleClientSecret)
    .WithEnvironment("Identity__Redis__Configuration", redis.Resource.ConnectionStringExpression)
    .WithEnvironment("Identity__SmsLogin__HookSecret", smsHookSecret)
    .WithHttpHealthCheck("/health/live")
    .WaitFor(keycloak)
    .WaitFor(redis);

var gatewayHttp = gateway.GetEndpoint("http");
// Keycloak (a container) calls the gateway to deliver SMS sign-in codes; Aspire resolves the host address for it.
keycloak.WithEnvironment("AVASH_GATEWAY_URL", gatewayHttp);
gateway.WithEnvironment("Identity__PublicBaseUrl", gatewayHttp);

// Persian (RTL) admin console: signs in through Keycloak (Avash login theme) and calls the gateway API.
builder.AddProject<Projects.Identity_Admin>("identity-admin")
    .WithEnvironment("Console__KeycloakBaseUrl", keycloakHttp)
    .WithEnvironment("Console__GatewayBaseUrl", gatewayHttp)
    .WithEnvironment("Console__ClientSecret", adminConsoleClientSecret)
    .WithEnvironment("Console__Tenants__0__Id", "avash")
    .WithEnvironment("Console__Tenants__0__DisplayName", "آوش")
    .WithEnvironment("Console__Tenants__0__Realm", KeycloakRealm)
    .WithHttpHealthCheck("/alive")
    .WaitFor(gateway);

// Fail at once (not after Aspire's two-minute orchestrator timeout) when another stack holds the fixed ports.
if (builder.ExecutionContext.IsRunMode)
    PortPreflight.EnsureFree((5080, "identity-gateway"), (5090, "identity-admin"), (KeycloakPort, "keycloak"));

builder.Build().Run();

// Realms, themes and providers live in the repository's keycloak/ folder (next to the Java extensions).
string KeycloakAssets(string folder) => Path.GetFullPath(Path.Combine(builder.AppHostDirectory, "..", "..", "..", "keycloak", folder));

IResourceBuilder<ParameterResource> ClientSecret(string name) => builder.AddParameter(
    name, new GenerateParameterDefault { MinLength = 32, Special = false }, secret: true, persist: true);
