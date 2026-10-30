using Avash.Identity.Authentication.AspNetCore;
using Avash.Identity.Authorization.AspNetCore;
using Identity.Gateway;
using Identity.Application;
using Identity.Contracts;
using FluentValidation;
using Identity.Gateway.Errors;
using Scalar.AspNetCore;
using Identity.Gateway.Bootstrap;

var builder = WebApplication.CreateBuilder(args);
builder.AddServiceDefaults();
var authority = builder.Configuration["Identity:Authority"] ??
                throw new InvalidOperationException("Identity:Authority is required.");
var audience = builder.Configuration["Identity:Audience"] ?? string.Empty;
var requireHttpsMetadata = builder.Configuration["Identity:RequireHttpsMetadata"] ?? "false";

if (builder.Environment.IsDevelopment())
{
    Microsoft.IdentityModel.Logging.IdentityModelEventSource.ShowPII = true;
}

builder.Services.AddSingleton(TimeProvider.System);
// One error contract: RFC 9457 problem details with a stable "code" (see Errors/ErrorResults).
builder.Services.AddProblemDetails();
builder.Services.AddExceptionHandler<Identity.Gateway.Errors.GlobalExceptionHandler>();
builder.Services.AddValidatorsFromAssemblyContaining<ProvisioningOrchestrator>(includeInternalTypes: true);
builder.Services.AddHttpContextAccessor();
builder.Services.AddHttpClient();
builder.Services.AddScoped<ICurrentUserContext, HttpCurrentUserContext>();
builder.Services.AddAvashAuthentication(options =>
{
    options.Authority = authority;
    options.Audience = audience;
    options.RequireHttpsMetadata = bool.TryParse(requireHttpsMetadata, out var result) && result;
});
builder.Services.AddAvashAuthorization();
builder.Services.AddGrpc();

builder.Services.Configure<Identity.Infrastructure.Keycloak.KeycloakOptions>(
    builder.Configuration.GetSection("Identity:KeycloakAdmin"));
builder.Services.AddSingleton<IAuditSink>(sp => new Identity.Infrastructure.NoopAuditSink());
builder.Services.AddSingleton<ICacheInvalidationService, Identity.Infrastructure.Redis.RedisCacheInvalidator>();
builder.Services.AddSingleton<IDatabaseDiagnosticsService, Identity.Infrastructure.Database.DatabaseDiagnosticsService>();

// Directory, user sessions, roles & permissions — Keycloak is source of truth
builder.Services.AddHttpClient<Identity.Infrastructure.Keycloak.KeycloakDirectoryAdapter>();
builder.Services.AddSingleton<IUserDirectory>(sp =>
    sp.GetRequiredService<Identity.Infrastructure.Keycloak.KeycloakDirectoryAdapter>());
builder.Services.AddSingleton<IUserSessionService>(sp =>
    sp.GetRequiredService<Identity.Infrastructure.Keycloak.KeycloakDirectoryAdapter>());
builder.Services.AddSingleton<IRoleDirectory>(sp =>
    sp.GetRequiredService<Identity.Infrastructure.Keycloak.KeycloakDirectoryAdapter>());
// Registered permissions are mirrored into Keycloak client roles per owning service client
// so they reach token claims through the per-client oidc-usermodel-client-role-mapper.
// Legacy realm-role path kept as fallback for tests / not-yet-migrated callers.
// Mirroring is best-effort and never blocks registration or startup.
builder.Services.AddHttpClient<Identity.Infrastructure.Keycloak.KeycloakClientRoleProvisioner>();
builder.Services.AddTransient<IKeycloakClientRoleProvisioner>(sp =>
    sp.GetRequiredService<Identity.Infrastructure.Keycloak.KeycloakClientRoleProvisioner>());
// Applications and their permission catalog (clients and client roles in Keycloak).
builder.Services.AddHttpClient<Identity.Infrastructure.Keycloak.KeycloakApplicationCatalog>();
builder.Services.AddTransient<Identity.Application.Permissions.IApplicationCatalog>(sp =>
    sp.GetRequiredService<Identity.Infrastructure.Keycloak.KeycloakApplicationCatalog>());
builder.Services.AddTransient<Identity.Application.Permissions.IPermissionCatalog>(sp =>
    sp.GetRequiredService<Identity.Infrastructure.Keycloak.KeycloakApplicationCatalog>());

// Dynamic roles/scope infrastructure
builder.Services.AddMemoryCache();
// Shared L2 cache (Redis) so multiple gateway replicas invalidate each other's registry copies.
var redisConfig = builder.Configuration["Identity:Redis:Configuration"];
if (!string.IsNullOrWhiteSpace(redisConfig))
    builder.Services.AddStackExchangeRedisCache(o => o.Configuration = redisConfig);
builder.Services.ConfigureHttpJsonOptions(o => o.SerializerOptions.Converters.Add(new ScopeDictionaryConverter()));
builder.Services.Configure<ScopedAccessOptions>(
    builder.Configuration.GetSection("Identity:ScopedAccess"));
builder.Services.AddSingleton<IScopedAccessSerializer, ScopedAccessSerializer>();
builder.Services
    .AddSingleton<Identity.Application.Scope.IScopeValueValidator,
        Identity.Application.Scope.DefaultScopeValueValidator>();
builder.Services.AddSingleton<Identity.Application.Scope.IScopeValueValidatorRegistry,
    Identity.Application.Scope.ScopeValueValidatorRegistry>();
builder.Services.AddSingleton<Identity.Application.Scope.ScopeAssignmentValidator>();
// Scope registry backed by the reserved group iam-scope-registry.
builder.Services.AddHttpClient<Identity.Infrastructure.Keycloak.Scope.KeycloakScopeRegistryStore>();
builder.Services.AddSingleton<Identity.Application.Scope.IScopeDefinitionLookup>(sp =>
    sp.GetRequiredService<Identity.Infrastructure.Keycloak.Scope.KeycloakScopeRegistryStore>());
builder.Services.AddScoped<Identity.Application.Scope.IResourceScopeResolver>(sp =>
    sp.GetRequiredService<Identity.Infrastructure.Keycloak.Scope.KeycloakScopeRegistryStore>());
builder.Services.AddScoped<Identity.Application.Scope.IScopeCacheInvalidator>(sp =>
    sp.GetRequiredService<Identity.Infrastructure.Keycloak.Scope.KeycloakScopeRegistryStore>());
builder.Services.AddScoped<Identity.Application.Scope.IScopeRegistryAdmin>(sp =>
    sp.GetRequiredService<Identity.Infrastructure.Keycloak.Scope.KeycloakScopeRegistryStore>());
builder.Services.AddHttpClient<Identity.Infrastructure.Keycloak.Scope.KeycloakScopeAttributeStore>();
builder.Services.AddScoped<Identity.Application.Scope.IUserScopeReader>(sp =>
    sp.GetRequiredService<Identity.Infrastructure.Keycloak.Scope.KeycloakScopeAttributeStore>());
builder.Services.AddSingleton<Identity.Infrastructure.Keycloak.KeycloakAdminTokenCache>();
builder.Services.AddHttpClient<Identity.Infrastructure.Keycloak.KeycloakAdminTokenProvider>();
builder.Services.AddHttpClient<Identity.Infrastructure.Keycloak.KeycloakGroupBusinessRoleStore>();
builder.Services.AddSingleton<IBusinessRoleStore>(sp =>
    sp.GetRequiredService<Identity.Infrastructure.Keycloak.KeycloakGroupBusinessRoleStore>());
// One scope store: IScopedAccessStore (the user's own assignments) and IUserScopeReader (merged view).
builder.Services.AddSingleton<IScopedAccessStore>(sp =>
    sp.GetRequiredService<Identity.Infrastructure.Keycloak.Scope.KeycloakScopeAttributeStore>());
builder.Services.AddHttpClient<Identity.Infrastructure.Keycloak.KeycloakUserProvisioner>();
builder.Services.AddSingleton<IUserProvisioningService>(sp =>
    sp.GetRequiredService<Identity.Infrastructure.Keycloak.KeycloakUserProvisioner>());
builder.Services.AddHttpClient<Identity.Infrastructure.Keycloak.KeycloakUserGroupMembership>();
builder.Services.AddSingleton<IUserRoleMapping>(sp =>
    sp.GetRequiredService<Identity.Infrastructure.Keycloak.KeycloakUserGroupMembership>());
builder.Services.AddScoped<ProvisioningOrchestrator>(sp =>
    new ProvisioningOrchestrator(
        sp.GetRequiredService<IUserProvisioningService>(),
        sp.GetRequiredService<IScopedAccessStore>(),
        sp.GetRequiredService<IBusinessRoleStore>(),
        sp.GetRequiredService<IUserRoleMapping>(),
        sp.GetRequiredService<Identity.Application.Scope.ScopeAssignmentValidator>(),
        sp.GetRequiredService<IUserProfileRequirements>()));
builder.Services.AddHttpClient<Identity.Infrastructure.Keycloak.KeycloakIamAccessClaimMapper>();
builder.Services.AddHttpClient<Identity.Infrastructure.Keycloak.KeycloakScopeClaimMapper>();
builder.Services.AddTransient<Identity.Infrastructure.Keycloak.Scope.IScopeAttributeProvisioner,
    Identity.Infrastructure.Keycloak.Scope.ScopeAttributeProvisioner>();
// Singleton so the cached required-profile attributes are shared by every endpoint and the
// orchestrator; AddHttpClient alone would register it transient and defeat the cache.
builder.Services.AddSingleton<Identity.Infrastructure.Keycloak.KeycloakUserProfileHardening>(sp =>
    new Identity.Infrastructure.Keycloak.KeycloakUserProfileHardening(
        sp.GetRequiredService<IHttpClientFactory>()
            .CreateClient(nameof(Identity.Infrastructure.Keycloak.KeycloakUserProfileHardening)),
        Microsoft.Extensions.Options.Options.Create(
            sp.GetRequiredService<Microsoft.Extensions.Options.IOptions<Identity.Infrastructure.Keycloak.KeycloakOptions>>().Value),
        sp.GetRequiredService<Identity.Infrastructure.Keycloak.KeycloakAdminTokenProvider>(),
        sp.GetRequiredService<ILogger<Identity.Infrastructure.Keycloak.KeycloakUserProfileHardening>>()));
builder.Services.AddSingleton<IUserProfileRequirements>(sp =>
    sp.GetRequiredService<Identity.Infrastructure.Keycloak.KeycloakUserProfileHardening>());
builder.Services.AddTransient<Identity.Infrastructure.Keycloak.GatewayPermissionRegistrar>();


builder.Services.AddHealthChecks();
// Prepares Keycloak (scope registry, claim mappers, gateway permissions, super-admins) with retries;
// the gateway reports unhealthy until that has succeeded.
builder.Services.AddKeycloakBootstrap();

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddOpenApi("v1", o =>
{
    o.AddDocumentTransformer((document, _, _) =>
    {
        document.Info.Title = "Identity Gateway";
        document.Info.Description =
            "Keycloak-centric gateway — auth proxy, directory, permissions, key lifecycle. " +
            "Present a Keycloak-issued JWT via the Bearer scheme below; privileged groups need the " +
            "matching Identity.* permission claims (e.g. identity.users.manage, identity.roles.manage).";
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
// Registered before everything else so no exception reaches the developer page, which would
// echo request headers (including bearer tokens) back to the caller.
app.UseExceptionHandler();
app.UseStatusCodePages();
app.MapDefaultEndpoints();
if (app.Environment.IsDevelopment())
{
    // Scalar reads the Microsoft.OpenApi document at /openapi/v1.json — full interactive UI
    // with "Try it" requests against every REST group.
    app.MapScalarApiReference(options => options
        .WithTitle("Identity Gateway")
        .WithOpenApiRoutePattern("/openapi/v1.json")
        .AddPreferredSecuritySchemes(["Bearer"]));
}

app.MapOpenApi();
// No HTTPS endpoint exists in Development/compose (plain HTTP on 5080), so a redirect here would 307 every request.
if (!app.Environment.IsDevelopment()) app.UseHttpsRedirection();
app.UseDefaultFiles();
app.UseStaticFiles();
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
app.MapGet("/api/system/database-info", async (IDatabaseDiagnosticsService dbService, CancellationToken ct) =>
    Results.Ok(await dbService.CheckStatusAsync(ct)))
    .RequireAuthorization(IamPermissions.SystemRead)
    .WithName("GetDatabaseInfo")
    .WithTags("System")
    .Produces<Identity.Contracts.Diagnostics.DatabaseStatusDto>(200);
app.MapGrpcService<Avash.Identity.Grpc.IdentityGrpcService>();
app.MapGet("/dashboard", () => Results.Redirect("/"));
// Unknown API routes answer with a 404 problem instead of the dashboard page.
app.MapFallback("/api/{**path}", () =>
    Error.NotFound("route.not_found", "No API endpoint matches this path.").ToProblem());
app.MapFallbackToFile("index.html");
app.Run();

public partial class Program;