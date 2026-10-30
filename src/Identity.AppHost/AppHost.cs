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

var keycloak = builder.AddKeycloak("keycloak", port: KeycloakPort, keycloakAdmin, keycloakAdminPassword)
    .WithImageTag(KeycloakImageTag)
    .WithRealmImport("./Keycloak/Realms")
    .WithEnvironment("KC_DB", "postgres")
    .WithEnvironment("KC_DB_URL", ReferenceExpression.Create(
        $"jdbc:postgresql://{postgres.Resource.PrimaryEndpoint.Property(EndpointProperty.HostAndPort)}/{keycloakDb.Resource.DatabaseName}"))
    .WithEnvironment("KC_DB_USERNAME", postgres.Resource.UserNameReference)
    .WithEnvironment("KC_DB_PASSWORD", postgres.Resource.PasswordParameter)
    .WaitFor(keycloakDb);

var keycloakHttp = keycloak.GetEndpoint("http");

var gateway = builder.AddProject<Projects.Identity_Gateway>("identity-gateway")
    .WithEnvironment("Identity__Authority", ReferenceExpression.Create($"{keycloakHttp}/realms/{KeycloakRealm}"))
    .WithEnvironment("Identity__Keycloak__BaseUrl", keycloakHttp)
    .WithEnvironment("Identity__Keycloak__Realm", KeycloakRealm)
    .WithEnvironment("Identity__KeycloakAdmin__BaseUrl", keycloakHttp)
    .WithEnvironment("Identity__KeycloakAdmin__Realm", KeycloakRealm)
    .WithEnvironment("Identity__KeycloakAdmin__AdminUsername", keycloakAdmin)
    .WithEnvironment("Identity__KeycloakAdmin__AdminPassword", keycloakAdminPassword)
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
    .WithHttpHealthCheck("/health/live")
    .WaitFor(gateway);

builder.Build().Run();
