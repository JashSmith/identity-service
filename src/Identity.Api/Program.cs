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
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddHttpContextAccessor();
builder.Services.AddHttpClient();
builder.Services.AddScoped<ICurrentUserContext, HttpCurrentUserContext>();
builder.Services.AddCompanyAuthentication(options =>
{
    options.Authority = authority;
    options.Audience = audience;
    options.RequireHttpsMetadata = !builder.Environment.IsDevelopment();
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
// Registered permissions are mirrored into Keycloak realm roles so they reach token claims
// through the existing oidc-usermodel-realm-role-mapper. Mirroring is best-effort and never
// blocks registration or startup.
builder.Services.AddHttpClient<Identity.Infrastructure.Keycloak.KeycloakRoleProvisioner>();
builder.Services.AddSingleton<IKeycloakRoleProvisioner>(sp =>
    sp.GetRequiredService<Identity.Infrastructure.Keycloak.KeycloakRoleProvisioner>());
builder.Services.AddSingleton<InMemoryPermissionRegistry>();
builder.Services.AddSingleton<IPermissionRegistry>(sp => new KeycloakSyncingPermissionRegistry(
    sp.GetRequiredService<InMemoryPermissionRegistry>(),
    sp.GetRequiredService<IKeycloakRoleProvisioner>(),
    sp.GetRequiredService<ILogger<KeycloakSyncingPermissionRegistry>>()));
builder.Services.AddSingleton<PermissionRegistrationService>();

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
app.MapPermissions();
app.MapAdminKeys();
app.MapGrpcService<Company.Identity.Grpc.IdentityGrpcService>();
app.MapGrpcService<Company.Identity.Grpc.KeyAdminGrpcService>();
app.MapPost("/api/identity/external/organization-token",
        (OrganizationTokenRequest request) => Results.StatusCode(StatusCodes.Status501NotImplemented))
    .WithTags("Auth").WithName("ExchangeOrganizationToken");
app.Run();

public partial class Program;