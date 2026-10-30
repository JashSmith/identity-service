// Local orchestration for the Identity Gateway stack:
// PostgreSQL (Keycloak's database) -> Keycloak -> Identity Gateway -> sample consumer, plus Redis as cache.
// The gateway keeps no database of its own; Keycloak is the single source of truth.

const string KeycloakRealm = "company";
const string KeycloakImageTag = "26.4";
// Fixed so the token issuer stays stable across runs; 8080 is avoided because it is
// commonly taken by other local web servers.
const int KeycloakPort = 18080;

var builder = DistributedApplication.CreateBuilder(args);

var postgres = builder.AddPostgres("postgres")
    .WithDataVolume()
    .WithLifetime(ContainerLifetime.Persistent);
var keycloakDb = postgres.AddDatabase("keycloak-db", databaseName: "keycloak");

var redis = builder.AddRedis("redis")
    .WithDataVolume();

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
var orderServiceClientSecret = ClientSecret("order-service-client-secret");
var gatewayAdminClientSecret = ClientSecret("gateway-admin-client-secret");
// Second, demo tenant (realm "acme") with its own gateway clients: shows one-realm-per-tenant locally.
var acmeGatewayClientSecret = ClientSecret("acme-gateway-client-secret");
var acmeGatewayAdminClientSecret = ClientSecret("acme-gateway-admin-client-secret");

var keycloak = builder.AddKeycloak("keycloak", port: KeycloakPort, keycloakAdmin, keycloakAdminPassword)
    .WithImageTag(KeycloakImageTag)
    .WithRealmImport("./Keycloak/Realms")
    // Custom themes (e.g. "avash": Persian RTL login); Keycloak's built-in themes live in its jars, not in this folder.
    .WithBindMount("./Keycloak/Themes", "/opt/keycloak/themes", isReadOnly: true)
    .WithEnvironment("KC_DB", "postgres")
    .WithEnvironment("KC_DB_URL", ReferenceExpression.Create(
        $"jdbc:postgresql://{postgres.Resource.PrimaryEndpoint.Property(EndpointProperty.HostAndPort)}/{keycloakDb.Resource.DatabaseName}"))
    .WithEnvironment("KC_DB_USERNAME", postgres.Resource.UserNameReference)
    .WithEnvironment("KC_DB_PASSWORD", postgres.Resource.PasswordParameter)
    .WithEnvironment("GATEWAY_CLIENT_SECRET", gatewayClientSecret)
    .WithEnvironment("ORDER_SERVICE_CLIENT_SECRET", orderServiceClientSecret)
    .WithEnvironment("GATEWAY_ADMIN_CLIENT_SECRET", gatewayAdminClientSecret)
    .WithEnvironment("ACME_GATEWAY_CLIENT_SECRET", acmeGatewayClientSecret)
    .WithEnvironment("ACME_GATEWAY_ADMIN_CLIENT_SECRET", acmeGatewayAdminClientSecret)
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
    .WithEnvironment("Identity__Tenants__0__Id", "acme")
    .WithEnvironment("Identity__Tenants__0__DisplayName", "Acme (demo tenant)")
    .WithEnvironment("Identity__Tenants__0__Realm", "acme")
    .WithEnvironment("Identity__Tenants__0__AdminClientSecret", acmeGatewayAdminClientSecret)
    .WithEnvironment("Identity__Tenants__0__ClientSecret", acmeGatewayClientSecret)
    .WithEnvironment("Identity__Redis__Configuration", redis.Resource.ConnectionStringExpression)
    .WithEnvironment("Database__Provider", "postgres")
    .WithEnvironment("Database__ConnectionStrings__postgres", keycloakDb.Resource.ConnectionStringExpression)
    .WithHttpHealthCheck("/health/live")
    .WaitFor(keycloak)
    .WaitFor(redis);

var gatewayHttp = gateway.GetEndpoint("http");
gateway.WithEnvironment("Identity__PublicBaseUrl", gatewayHttp);

builder.AddProject<Projects.OrderService_Sample>("order-service")
    .WithEnvironment("Identity__Authority", gatewayHttp)
    .WithEnvironment("PermissionRegistration__IdentityServer", gatewayHttp)
    .WithEnvironment("PermissionRegistration__ClientSecret", orderServiceClientSecret)
    .WithHttpHealthCheck("/health/live")
    .WaitFor(gateway);

builder.Build().Run();

IResourceBuilder<ParameterResource> ClientSecret(string name) => builder.AddParameter(
    name, new GenerateParameterDefault { MinLength = 32, Special = false }, secret: true, persist: true);
