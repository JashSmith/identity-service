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
builder.Services.Configure<Identity.Application.KeyManagementOptions>(
    builder.Configuration.GetSection("Identity:KeyManagement"));
builder.Services.Configure<Identity.Infrastructure.Vault.VaultOptions>(
    builder.Configuration.GetSection("Identity:Vault"));
builder.Services.Configure<Identity.Infrastructure.Keycloak.KeycloakOptions>(
    builder.Configuration.GetSection("Identity:KeycloakAdmin"));
builder.Services.AddSingleton(sp =>
    sp.GetRequiredService<Microsoft.Extensions.Options.IOptions<Identity.Application.KeyManagementOptions>>().Value);
builder.Services
    .AddSingleton<Identity.Application.IKeyGenerationService, Identity.Infrastructure.RsaKeyGenerationService>();
builder.Services.AddSingleton<Identity.Application.IKeyRetirementSafety, Identity.Infrastructure.KeyRetirementSafety>();
builder.Services
    .AddSingleton<Identity.Application.IKeyRotationLock, Identity.Infrastructure.Redis.InMemoryKeyRotationLock>();
builder.Services.AddSingleton<Identity.Application.IAuditSink>(sp => new Identity.Infrastructure.NoopAuditSink());
builder.Services.AddHttpClient<Identity.Infrastructure.Vault.VaultSigningKeyStore>();
builder.Services.AddSingleton<Identity.Application.ISigningKeyVault>(sp =>
    sp.GetRequiredService<Identity.Infrastructure.Vault.VaultSigningKeyStore>());
builder.Services.AddHttpClient<Identity.Infrastructure.Keycloak.KeycloakKeyManager>();
builder.Services.AddSingleton<Identity.Application.IKeycloakKeyManager>(sp =>
    sp.GetRequiredService<Identity.Infrastructure.Keycloak.KeycloakKeyManager>());
builder.Services.AddDbContext<Identity.Persistence.KeyManagement.KeyMetadataDbContext>((sp, o) =>
{
    var cfg = sp.GetRequiredService<Microsoft.Extensions.Configuration.IConfiguration>();
    var cs = cfg.GetConnectionString("KeyMetadata") ?? "Data Source=identity_keys.db";
    var provider = cfg["Identity:KeyMetadata:Provider"] ?? "sqlite";
    Identity.Persistence.KeyManagement.KeyMetadataDbContext.ConfigureProvider(o, provider, cs);
});
builder.Services
    .AddScoped<Identity.Application.IKeyLifecycleRepository,
        Identity.Persistence.KeyManagement.EfKeyLifecycleRepository>();
builder.Services.AddScoped<Identity.Application.KeyRotationService>();
builder.Services.AddHealthChecks();

builder.Services.AddOpenApi();

var app = builder.Build();
app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();
app.MapHealthChecks("/health/live");
app.MapGet("/api/identity/me", (ICurrentUserContext current) =>
        current.UserId is null
            ? Results.Unauthorized()
            : Results.Ok(new {current.UserId, current.Username, current.Roles, current.Permissions, current.SessionId}))
    .RequireAuthorization();
app.MapAdminKeys();
app.MapPost("/api/identity/external/organization-token", (OrganizationTokenRequest request) =>
    Results.StatusCode(StatusCodes.Status501NotImplemented));
app.Run();

public partial class Program;