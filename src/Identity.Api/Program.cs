using Company.Identity.Authentication.AspNetCore;
using Company.Identity.Authorization.AspNetCore;
using Identity.Api;
using Identity.Application;
using Identity.Contracts;

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
builder.Services.Configure<Identity.Infrastructure.Vault.VaultOptions>(builder.Configuration.GetSection("Identity:Vault"));
builder.Services.Configure<Identity.Infrastructure.Keycloak.KeycloakOptions>(builder.Configuration.GetSection("Identity:KeycloakAdmin"));
builder.Services.AddSingleton(sp => sp.GetRequiredService<Microsoft.Extensions.Options.IOptions<KeyManagementOptions>>().Value);
builder.Services.AddSingleton<IKeyGenerationService, Identity.Infrastructure.RsaKeyGenerationService>();
builder.Services.AddSingleton<IKeyRetirementSafety, Identity.Infrastructure.KeyRetirementSafety>();
builder.Services.AddSingleton<IKeyRotationLock, Identity.Infrastructure.Redis.InMemoryKeyRotationLock>();
builder.Services.AddSingleton<IAuditSink>(sp => new Identity.Infrastructure.NoopAuditSink());
builder.Services.AddHttpClient<Identity.Infrastructure.Vault.VaultSigningKeyStore>();
builder.Services.AddSingleton<ISigningKeyVault>(sp => sp.GetRequiredService<Identity.Infrastructure.Vault.VaultSigningKeyStore>());
builder.Services.AddHttpClient<Identity.Infrastructure.Keycloak.KeycloakKeyManager>();
builder.Services.AddSingleton<IKeycloakKeyManager>(sp => sp.GetRequiredService<Identity.Infrastructure.Keycloak.KeycloakKeyManager>());

// Directory + permissions — Keycloak is source of truth; facade registry is in-memory so failure never blocks start.
builder.Services.AddHttpClient<Identity.Infrastructure.Keycloak.KeycloakDirectoryAdapter>();
builder.Services.AddSingleton<IUserDirectory>(sp => sp.GetRequiredService<Identity.Infrastructure.Keycloak.KeycloakDirectoryAdapter>());
builder.Services.AddSingleton<IRoleDirectory>(sp => sp.GetRequiredService<Identity.Infrastructure.Keycloak.KeycloakDirectoryAdapter>());
builder.Services.AddSingleton<IPermissionRegistry, InMemoryPermissionRegistry>();
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
builder.Services.AddSwaggerGen(o =>
{
    o.SwaggerDoc("v1", new Microsoft.OpenApi.OpenApiInfo { Title = "Identity Facade", Version = "v1", Description = "Keycloak-centric facade — auth proxy, directory, permissions, key lifecycle" });
    o.AddSecurityDefinition("Bearer", new Microsoft.OpenApi.OpenApiSecurityScheme { Type = Microsoft.OpenApi.SecuritySchemeType.Http, Scheme = "bearer", BearerFormat = "JWT", Description = "Keycloak-issued JWT" });
});
builder.Services.AddOpenApi();

var app = builder.Build();
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v1/swagger.json", "Identity Facade v1"));
}
app.MapOpenApi();
// No HTTPS endpoint exists in Development/compose (plain HTTP on 5080), so a redirect here would 307 every request.
if (!app.Environment.IsDevelopment()) app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();
app.MapHealthChecks("/health/live");
app.MapGet("/api/identity/me", (ICurrentUserContext current) =>
        current.UserId is null ? Results.Unauthorized() : Results.Ok(new { current.UserId, current.Username, current.Roles, current.Permissions, current.SessionId }))
    .RequireAuthorization().WithTags("Users").WithName("Me").Produces<object>(200);
app.MapAuth();
app.MapUsers();
app.MapPermissions();
app.MapAdminKeys();
app.MapGrpcService<Company.Identity.Grpc.IdentityGrpcService>();
app.MapGrpcService<Company.Identity.Grpc.KeyAdminGrpcService>();
app.MapPost("/api/identity/external/organization-token", (OrganizationTokenRequest request) => Results.StatusCode(StatusCodes.Status501NotImplemented))
    .WithTags("Auth").WithName("ExchangeOrganizationToken");
app.Run();

public partial class Program;
