using Company.Identity.Authentication.AspNetCore;
using Company.Identity.Authorization.AspNetCore;
using Identity.Api;
using Identity.Application;
using Identity.Contracts;
using Scalar.AspNetCore;

var builder = WebApplication.CreateBuilder(args);
var authority = builder.Configuration["Identity:Authority"] ??
                throw new InvalidOperationException("Identity:Authority is required.");
var audience = builder.Configuration["Identity:Audience"] ?? string.Empty;
var requireHttpsMetadata = builder.Configuration["Identity:RequireHttpsMetadata"] ?? "false";

builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddHttpContextAccessor();
builder.Services.AddHttpClient();
builder.Services.AddScoped<ICurrentUserContext, HttpCurrentUserContext>();
builder.Services.AddCompanyAuthentication(options =>
{
    options.Authority = authority;
    options.Audience = audience;
    options.RequireHttpsMetadata = bool.TryParse(requireHttpsMetadata, out var result) && result;
});
builder.Services.AddCompanyAuthorization();
builder.Services.AddGrpc();

// Key management
builder.Services.Configure<KeyManagementOptions>(builder.Configuration.GetSection("Identity:KeyManagement"));
builder.Services.Configure<Identity.Infrastructure.Vault.VaultOptions>(
    builder.Configuration.GetSection("Identity:Vault"));
builder.Services.Configure<Identity.Infrastructure.Keycloak.KeycloakOptions>(
    builder.Configuration.GetSection("Identity:KeycloakAdmin"));
builder.Services.AddSingleton(sp =>
    sp.GetRequiredService<Microsoft.Extensions.Options.IOptions<KeyManagementOptions>>().Value);
builder.Services.AddSingleton<IKeyGenerationService, Identity.Infrastructure.RsaKeyGenerationService>();
builder.Services.AddScoped<IKeyRetirementSafety, Identity.Infrastructure.KeyRetirementSafety>();
builder.Services.AddSingleton<IKeyRotationLock, Identity.Infrastructure.Redis.InMemoryKeyRotationLock>();
builder.Services.AddSingleton<IAuditSink>(sp => new Identity.Infrastructure.NoopAuditSink());
builder.Services.AddHttpClient<Identity.Infrastructure.Vault.VaultSigningKeyStore>();
builder.Services.AddSingleton<ISigningKeyVault>(sp =>
    sp.GetRequiredService<Identity.Infrastructure.Vault.VaultSigningKeyStore>());
builder.Services.AddHttpClient<Identity.Infrastructure.Keycloak.KeycloakKeyManager>();
builder.Services.AddSingleton<IKeycloakKeyManager>(sp =>
    sp.GetRequiredService<Identity.Infrastructure.Keycloak.KeycloakKeyManager>());

// Directory + permissions — Keycloak is source of truth; facade registry is in-memory so failure never blocks start.
builder.Services.AddHttpClient<Identity.Infrastructure.Keycloak.KeycloakDirectoryAdapter>();
builder.Services.AddSingleton<IUserDirectory>(sp =>
    sp.GetRequiredService<Identity.Infrastructure.Keycloak.KeycloakDirectoryAdapter>());
builder.Services.AddSingleton<IRoleDirectory>(sp =>
    sp.GetRequiredService<Identity.Infrastructure.Keycloak.KeycloakDirectoryAdapter>());
// Registered permissions are mirrored into Keycloak client roles per owning service client
// so they reach token claims through the per-client oidc-usermodel-client-role-mapper.
// Legacy realm-role path kept as fallback for tests / not-yet-migrated callers.
// Mirroring is best-effort and never blocks registration or startup.
builder.Services.AddHttpClient<Identity.Infrastructure.Keycloak.KeycloakRoleProvisioner>();
builder.Services.AddSingleton<IKeycloakRoleProvisioner>(sp =>
    sp.GetRequiredService<Identity.Infrastructure.Keycloak.KeycloakRoleProvisioner>());
builder.Services.AddHttpClient<Identity.Infrastructure.Keycloak.KeycloakClientRoleProvisioner>();
builder.Services.AddSingleton<Identity.Application.IKeycloakClientRoleProvisioner>(sp =>
    sp.GetRequiredService<Identity.Infrastructure.Keycloak.KeycloakClientRoleProvisioner>());
builder.Services.AddSingleton<InMemoryPermissionRegistry>();
builder.Services.AddSingleton<IPermissionRegistry>(sp => new KeycloakSyncingPermissionRegistry(
    sp.GetRequiredService<InMemoryPermissionRegistry>(),
    sp.GetRequiredService<IKeycloakRoleProvisioner>(),
    sp.GetRequiredService<Identity.Application.IKeycloakClientRoleProvisioner>(),
    sp.GetRequiredService<ILogger<KeycloakSyncingPermissionRegistry>>()));
builder.Services.AddSingleton<PermissionRegistrationService>();

// Dynamic roles/scope infrastructure
builder.Services.AddMemoryCache();
builder.Services.ConfigureHttpJsonOptions(o => o.SerializerOptions.Converters.Add(new ScopeDictionaryConverter()));
builder.Services.Configure<Identity.Application.ScopedAccessOptions>(
    builder.Configuration.GetSection("Identity:ScopedAccess"));
builder.Services.AddSingleton<Identity.Application.IScopedAccessSerializer, Identity.Application.ScopedAccessSerializer>();
builder.Services.AddSingleton<Identity.Application.Scope.IScopeValueValidator, Identity.Application.Scope.DefaultScopeValueValidator>();
builder.Services.AddSingleton<Identity.Application.Scope.IScopeValueValidatorRegistry, Identity.Application.Scope.ScopeValueValidatorRegistry>();
builder.Services.AddSingleton<Identity.Application.Scope.ScopeAssignmentValidator>();
// Primary (Keycloak) scope registry — backed by the dedicated Group iam-scope-registry + authz.* attributes.
// EF fallbacks kept as secondary registrations (tests / migration window) but not the default resolution.
builder.Services.AddHttpClient<Identity.Infrastructure.Keycloak.Scope.KeycloakScopeRegistryStore>();
builder.Services.AddSingleton<Identity.Application.Scope.IScopeDefinitionLookup>(sp => sp.GetRequiredService<Identity.Infrastructure.Keycloak.Scope.KeycloakScopeRegistryStore>());
builder.Services.AddScoped<Identity.Application.Scope.IResourceScopeResolver>(sp => sp.GetRequiredService<Identity.Infrastructure.Keycloak.Scope.KeycloakScopeRegistryStore>());
builder.Services.AddScoped<Identity.Application.Scope.IScopeCacheInvalidator>(sp => sp.GetRequiredService<Identity.Infrastructure.Keycloak.Scope.KeycloakScopeRegistryStore>());
builder.Services.AddScoped<Identity.Persistence.KeyManagement.EfScopeDefinitionLookup>();
builder.Services.AddScoped<Identity.Persistence.KeyManagement.EfResourceScopeResolver>();
builder.Services.AddHttpClient<Identity.Infrastructure.Keycloak.Scope.KeycloakScopeAttributeStore>();
builder.Services.AddScoped<Identity.Application.Scope.IUserScopeReader>(sp => sp.GetRequiredService<Identity.Infrastructure.Keycloak.Scope.KeycloakScopeAttributeStore>());
builder.Services.AddScoped<Identity.Application.Scope.IUserScopeWriter>(sp => sp.GetRequiredService<Identity.Infrastructure.Keycloak.Scope.KeycloakScopeAttributeStore>());
builder.Services.AddScoped<Identity.Persistence.KeyManagement.EfUserScopeStore>();
builder.Services.AddHttpClient<Identity.Infrastructure.Keycloak.KeycloakAdminTokenProvider>();
builder.Services.AddHttpClient<Identity.Infrastructure.Keycloak.KeycloakCompositeRoleStore>();
builder.Services.AddHttpClient<Identity.Infrastructure.Keycloak.KeycloakGroupBusinessRoleStore>();
builder.Services.AddSingleton<Identity.Application.IBusinessRoleStore>(sp =>
    sp.GetRequiredService<Identity.Infrastructure.Keycloak.KeycloakGroupBusinessRoleStore>());
builder.Services.AddHttpClient<Identity.Infrastructure.Keycloak.KeycloakScopedAccessStore>();
builder.Services.AddSingleton<Identity.Application.IScopedAccessStore>(sp =>
    sp.GetRequiredService<Identity.Infrastructure.Keycloak.KeycloakScopedAccessStore>());
builder.Services.AddHttpClient<Identity.Infrastructure.Keycloak.KeycloakUserProvisioner>();
builder.Services.AddSingleton<Identity.Application.IUserProvisioningService>(sp =>
    sp.GetRequiredService<Identity.Infrastructure.Keycloak.KeycloakUserProvisioner>());
builder.Services.AddHttpClient<Identity.Infrastructure.Keycloak.KeycloakUserRoleMapping>();
builder.Services.AddHttpClient<Identity.Infrastructure.Keycloak.KeycloakUserGroupMembership>();
builder.Services.AddSingleton<Identity.Application.IUserRoleMapping>(sp =>
    sp.GetRequiredService<Identity.Infrastructure.Keycloak.KeycloakUserGroupMembership>());
builder.Services.AddScoped<Identity.Application.ProvisioningOrchestrator>(sp =>
    new Identity.Application.ProvisioningOrchestrator(
        sp.GetRequiredService<Identity.Application.IUserProvisioningService>(),
        sp.GetRequiredService<Identity.Application.IScopedAccessStore>(),
        sp.GetRequiredService<Identity.Application.IBusinessRoleStore>(),
        sp.GetRequiredService<Identity.Application.IUserRoleMapping>(),
        sp.GetRequiredService<Identity.Application.IPermissionRegistry>(),
        sp.GetRequiredService<Identity.Application.Scope.ScopeAssignmentValidator>(),
        sp.GetRequiredService<Identity.Application.Scope.IUserScopeWriter>()));
builder.Services.AddHttpClient<Identity.Infrastructure.Keycloak.KeycloakIamAccessClaimMapper>();
builder.Services.AddHttpClient<Identity.Infrastructure.Keycloak.KeycloakScopeClaimMapper>();
builder.Services.AddHttpClient<Identity.Infrastructure.Keycloak.KeycloakUserProfileHardening>();
builder.Services.AddHttpClient<Identity.Infrastructure.Keycloak.FacadePermissionRegistrar>();


builder.Services.AddDbContext<Identity.Persistence.KeyManagement.KeyMetadataDbContext>((sp, o) =>
{
    var cfg = sp.GetRequiredService<IConfiguration>();
    var cs = cfg.GetConnectionString("KeyMetadata") ?? "Data Source=identity_keys.db";
    var provider = cfg["Identity:KeyMetadata:Provider"] ?? "sqlite";
    Identity.Persistence.KeyManagement.KeyMetadataDbContext.ConfigureProvider(o, provider, cs);
});
builder.Services.AddScoped<IKeyLifecycleRepository, Identity.Persistence.KeyManagement.EfKeyLifecycleRepository>();
builder.Services.AddScoped<KeyRotationService>();
builder.Services.AddHealthChecks();

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddOpenApi("v1", o =>
{
    o.AddDocumentTransformer((document, _, _) =>
    {
        document.Info.Title = "Identity Facade";
        document.Info.Description =
            "Keycloak-centric facade — auth proxy, directory, permissions, key lifecycle. " +
            "Present a Keycloak-issued JWT via the Bearer scheme below; privileged groups need the " +
            "matching Identity.* permission claims (e.g. Identity.Keys.Generate for key admin routes).";
        var bearer = new Microsoft.OpenApi.OpenApiSecurityScheme
        {
            Type = Microsoft.OpenApi.SecuritySchemeType.Http,
            Scheme = "bearer",
            BearerFormat = "JWT",
            Description = "Keycloak-issued JWT"
        };
        var components = document.Components ?? new Microsoft.OpenApi.OpenApiComponents();
        document.Components = components;
        components.SecuritySchemes ??= new Dictionary<string, Microsoft.OpenApi.IOpenApiSecurityScheme>();
        components.SecuritySchemes["Bearer"] = bearer;
        document.Security =
        [
            new Microsoft.OpenApi.OpenApiSecurityRequirement
            {
                [new Microsoft.OpenApi.OpenApiSecuritySchemeReference("Bearer", document)] = []
            }
        ];
        return Task.CompletedTask;
    });
});

var app = builder.Build();
if (app.Environment.IsDevelopment())
{
    // Scalar reads the Microsoft.OpenApi document at /openapi/v1.json — full interactive UI
    // with "Try it" requests against every REST group.
    app.MapScalarApiReference(options => options
        .WithTitle("Identity Facade")
        .WithOpenApiRoutePattern("/openapi/v1.json")
        .AddPreferredSecuritySchemes(["Bearer"]));
}

app.MapOpenApi();
// No HTTPS endpoint exists in Development/compose (plain HTTP on 5080), so a redirect here would 307 every request.
if (!app.Environment.IsDevelopment()) app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();
app.MapHealthChecks("/health/live");
app.MapOidcProxy();
app.MapGet("/api/identity/me", (ICurrentUserContext current) =>
        current.UserId is null
            ? Results.Unauthorized()
            : Results.Ok(
                new { current.UserId, current.Username, current.Roles, current.Permissions, current.SessionId }))
    .RequireAuthorization()
    .WithTags("Users")
    .WithName("Me")
    .Produces<object>(200);
app.MapAuth();
app.MapUsers();
app.MapUserManagement();
app.MapBusinessRoles();
app.MapScopeAdmin();
app.MapAccessContext();
app.MapPermissions();
app.MapAdminKeys();
app.MapGrpcService<Company.Identity.Grpc.IdentityGrpcService>();
app.MapGrpcService<Company.Identity.Grpc.KeyAdminGrpcService>();
// Seed facade-owned permissions through the existing registry so they are mirrored to Keycloak.
try
{
    using var scope = app.Services.CreateScope();
    var registrar = scope.ServiceProvider.GetRequiredService<Identity.Infrastructure.Keycloak.FacadePermissionRegistrar>();
    var asm = typeof(Program).Assembly;
    // Use a short timeout for seeding; don't block startup on Keycloak availability.
    using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
    await registrar.RegisterAsync(asm, cts.Token);
}
catch { /* best-effort */ }

try
{
    using var scope2 = app.Services.CreateScope();
    var mapper = scope2.ServiceProvider.GetRequiredService<Identity.Infrastructure.Keycloak.KeycloakIamAccessClaimMapper>();
    using var cts2 = new CancellationTokenSource(TimeSpan.FromSeconds(10));
    await mapper.EnsureAsync(cts2.Token);
}
catch { /* best-effort */ }

try
{
    using var scope4 = app.Services.CreateScope();
    var scopeMapper = scope4.ServiceProvider.GetRequiredService<Identity.Infrastructure.Keycloak.KeycloakScopeClaimMapper>();
    using var cts4 = new CancellationTokenSource(TimeSpan.FromSeconds(10));
    await scopeMapper.EnsureAsync(cts4.Token);
}
catch { /* best-effort */ }

try
{
    using var scope5 = app.Services.CreateScope();
    var hardening = scope5.ServiceProvider.GetRequiredService<Identity.Infrastructure.Keycloak.KeycloakUserProfileHardening>();
    using var cts5 = new CancellationTokenSource(TimeSpan.FromSeconds(10));
    await hardening.EnsureAsync(cts5.Token);
}
catch { /* best-effort */ }

try
{
    using var scope3 = app.Services.CreateScope();
    var db = scope3.ServiceProvider.GetRequiredService<Identity.Persistence.KeyManagement.KeyMetadataDbContext>();
    using var cts3 = new CancellationTokenSource(TimeSpan.FromSeconds(10));
    await Identity.Persistence.KeyManagement.ScopeSeed.EnsureSeededAsync(db, cts3.Token);
}
catch { /* best-effort — Oracle auth tables are legacy; Keycloak iam-scope-registry is the source of truth */ }

app.MapPost("/api/identity/external/organization-token",
        (OrganizationTokenRequest request) => Results.StatusCode(StatusCodes.Status501NotImplemented))
    .WithTags("Auth").WithName("ExchangeOrganizationToken");
app.Run();

public partial class Program;