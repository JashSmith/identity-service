using Company.Identity.Authentication.AspNetCore;
using Company.Identity.Authorization.AspNetCore;
using Identity.Application;
using Identity.Contracts;
using Identity.Infrastructure;
using Microsoft.AspNetCore.Antiforgery;
using Identity.Persistence.EntityFrameworkCore;
using Identity.Domain;
using IdentityGrpcService = Company.Identity.Grpc.IdentityGrpcService;
using Identity.Messaging.RabbitMq;
using Identity.Api;
using Identity.Providers.Abstractions;
using Identity.Providers.Local;
using Identity.Providers.OpenIdConnect;
using Identity.Providers.Keycloak;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Authentication;

var builder = WebApplication.CreateBuilder(args);
var authority = builder.Configuration["Identity:Tokens:Issuer"] ?? "https://localhost:7001";
var audience = builder.Configuration["Identity:Tokens:Audience"] ?? "identity-api";
var signingKeys = new JwtSigningKeyProvider(builder.Configuration);
builder.Services.AddSingleton(signingKeys);
var connectionString = builder.Configuration.GetConnectionString("Identity") ?? "Data Source=identity.db";
var useSqlite = builder.Configuration.GetValue("Identity:Persistence:UseSqlite", true);
builder.Services.AddIdentityPersistence(connectionString, useSqlite);
builder.Services.AddScoped<LocalAuthenticationService>();
builder.Services.AddScoped<ExternalAuthenticationService>();
builder.Services.AddSingleton<IExternalIdentityProvider, LocalExternalIdentityProvider>();
var oidcAuthority = builder.Configuration["Identity:ExternalProviders:Oidc:Authority"];
if (!string.IsNullOrWhiteSpace(oidcAuthority))
{
    builder.Services.AddHttpClient<OpenIdConnectIdentityProvider>(client =>
    {
        client.Timeout = TimeSpan.FromSeconds(builder.Configuration.GetValue("Identity:ExternalProviders:Oidc:TimeoutSeconds", 10));
    });
    builder.Services.AddSingleton(sp => new OpenIdConnectOptions
    {
        Authority = oidcAuthority,
        ClientId = builder.Configuration["Identity:ExternalProviders:Oidc:ClientId"] ?? string.Empty,
        ClientSecret = builder.Configuration["Identity:ExternalProviders:Oidc:ClientSecret"],
        RequireHttpsMetadata = !builder.Environment.IsDevelopment(),
        Timeout = TimeSpan.FromSeconds(builder.Configuration.GetValue("Identity:ExternalProviders:Oidc:TimeoutSeconds", 10))
    });
    builder.Services.AddSingleton<IExternalIdentityProvider>(sp => sp.GetRequiredService<OpenIdConnectIdentityProvider>());
}
var keycloakAuthority = builder.Configuration["Identity:ExternalProviders:Keycloak:Authority"];
if (!string.IsNullOrWhiteSpace(keycloakAuthority))
{
    builder.Services.AddHttpClient<KeycloakIdentityProvider>(client =>
    {
        client.Timeout = TimeSpan.FromSeconds(builder.Configuration.GetValue("Identity:ExternalProviders:Keycloak:TimeoutSeconds", 10));
    });
    builder.Services.AddSingleton(sp => new KeycloakOptions
    {
        Authority = keycloakAuthority,
        ClientId = builder.Configuration["Identity:ExternalProviders:Keycloak:ClientId"] ?? string.Empty,
        ClientSecret = builder.Configuration["Identity:ExternalProviders:Keycloak:ClientSecret"],
        RequireHttpsMetadata = !builder.Environment.IsDevelopment(),
        Timeout = TimeSpan.FromSeconds(builder.Configuration.GetValue("Identity:ExternalProviders:Keycloak:TimeoutSeconds", 10))
    });
    builder.Services.AddSingleton<IExternalIdentityProvider>(sp => sp.GetRequiredService<KeycloakIdentityProvider>());
}
builder.Services.AddSingleton<IExternalIdentityProviderRegistry, ExternalIdentityProviderRegistry>();
builder.Services.AddSingleton<Identity.Application.ISystemClock>(_ => new Identity.Application.SystemClock(TimeProvider.System));
builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<ICurrentUserContext, HttpCurrentUserContext>();
builder.Services.AddSingleton<IPasswordVerifier, Pbkdf2PasswordVerifier>();
builder.Services.AddSingleton<IAccessTokenIssuer, JwtAccessTokenIssuer>();
builder.Services.AddScoped<PermissionManifestSynchronizer>();
builder.Services.AddOptions<PermissionManifestOptions>()
    .Bind(builder.Configuration.GetSection(PermissionManifestOptions.SectionName))
    .Validate(x => !string.IsNullOrWhiteSpace(x.ServiceId) && !string.IsNullOrWhiteSpace(x.ServiceName), "Permission manifest service metadata is required.")
    .ValidateOnStart();
builder.Services.AddHostedService<PermissionManifestHostedService>();
builder.Services.AddCompanyAuthentication(new Company.Identity.Authentication.IdentityAuthenticationOptions
{
    Authority = authority,
    Audiences = [audience],
    RequireHttpsMetadata = !builder.Environment.IsDevelopment(),
    SigningKey = signingKeys.Key,
    SigningKeys = signingKeys.PublicKeys.ToArray()
});
builder.Services.AddCompanyAuthorization();
builder.Services.AddCompanyBffSessions();
builder.Services.AddGrpc();
builder.Services.AddIdentityRabbitMq(builder.Configuration);
builder.Services.AddAntiforgery();
builder.Services.AddHealthChecks();
builder.Services.AddOpenApi();

var app = builder.Build();
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
    db.Database.EnsureCreated();
    var username = builder.Configuration["Identity:Bootstrap:Username"];
    var password = builder.Configuration["Identity:Bootstrap:Password"];
    if (!string.IsNullOrWhiteSpace(username) && !string.IsNullOrWhiteSpace(password) && !db.Users.Any(x => x.Username == username))
    {
        var clock = scope.ServiceProvider.GetRequiredService<Identity.Application.ISystemClock>();
        var user = new User(UserId.New(), username, username, clock.UtcNow);
        db.Users.Add(user);
        db.PasswordCredentials.Add(new PasswordCredential(user.Id, scope.ServiceProvider.GetRequiredService<IPasswordVerifier>().Hash(password), clock.UtcNow));
        db.SaveChanges();
    }
}
app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();
app.MapHealthChecks("/health/live");
app.MapGet("/.well-known/jwks.json", (JwtSigningKeyProvider keys) =>
{
    var publicKeys = keys.PublicKeys.Select(key =>
    {
        var parameters = key.Parameters;
        return new
        {
            kty = "RSA",
            use = "sig",
            alg = "RS256",
            kid = key.KeyId,
            n = Base64UrlEncoder.Encode(parameters.Modulus!),
            e = Base64UrlEncoder.Encode(parameters.Exponent!)
        };
    });
    return Results.Ok(new { keys = publicKeys });
});
app.MapGrpcService<IdentityGrpcService>();
app.MapGet("/api/users/me", (ICurrentUserContext currentUser) =>
{
    if (!currentUser.IsAuthenticated) return Results.Unauthorized();
    return Results.Ok(new UserResponse(
        currentUser.UserId ?? Guid.Empty,
        currentUser.Username ?? string.Empty,
        currentUser.DisplayName ?? currentUser.Username ?? string.Empty,
        currentUser.Roles,
        currentUser.Permissions,
        Guid.TryParse(currentUser.SessionId, out var sessionId) ? sessionId : null));
}).RequireAuthorization();
app.MapPost("/api/auth/login", async (LoginRequest request, LocalAuthenticationService authentication, CancellationToken cancellationToken) =>
{
    var result = await authentication.LoginAsync(request.Username, request.Password, cancellationToken);
    if (!result.Succeeded) return Results.Unauthorized();
    return Results.Ok(new TokenResponse(result.AccessToken!.AccessToken, result.RefreshToken!, result.AccessToken.ExpiresAt, result.SessionId!.Value));
});
app.MapPost("/api/auth/refresh", async (RefreshRequest request, LocalAuthenticationService authentication, CancellationToken cancellationToken) =>
{
    var result = await authentication.RefreshAsync(request.RefreshToken, cancellationToken);
    if (!result.Succeeded) return Results.Unauthorized();
    return Results.Ok(new TokenResponse(result.AccessToken!.AccessToken, result.RefreshToken!, result.AccessToken.ExpiresAt, result.SessionId!.Value));
});
app.MapPost("/api/auth/logout", async (HttpContext context, LocalAuthenticationService authentication, CancellationToken cancellationToken) =>
{
    if (!Guid.TryParse(context.User.FindFirst("sid")?.Value, out var sessionId)) return Results.NoContent();
    await authentication.LogoutAsync(sessionId, cancellationToken);
    return Results.NoContent();
}).RequireAuthorization();
app.MapGet("/api/auth/session", (HttpContext context) => Results.Ok(new { authenticated = context.User.Identity?.IsAuthenticated == true }));
app.MapPost("/api/auth/external/link", async (
    ExternalIdentityLinkRequest request,
    ICurrentUserContext currentUser,
    ExternalIdentityLinkingService linking,
    CancellationToken cancellationToken) =>
{
    if (!currentUser.IsAuthenticated || currentUser.UserId is null)
        return Results.Unauthorized();

    var result = await linking.LinkAsync(
        new UserId(currentUser.UserId.Value),
        new ExternalIdentityDescriptor(request.Provider, request.Subject, null, null),
        cancellationToken);
    return result.Succeeded ? Results.NoContent() : Results.Conflict(new ProblemResponse(
        result.ErrorCode ?? "external_identity_link_failed",
        "The external identity could not be linked.",
        Guid.NewGuid().ToString("N")));
}).RequireAuthorization();
app.MapPost("/api/auth/antiforgery", (HttpContext context, IAntiforgery antiforgery) =>
{
    var tokens = antiforgery.GetAndStoreTokens(context);
    return Results.Ok(new { token = tokens.RequestToken });
});
app.MapPost("/api/auth/bff/sign-in", async (
    LoginRequest request,
    LocalAuthenticationService authentication,
    HttpContext context,
    IAntiforgery antiforgery,
    CancellationToken cancellationToken) =>
{
    var result = await authentication.LoginAsync(request.Username, request.Password, cancellationToken);
    if (!result.Succeeded || result.SessionId is null)
        return Results.Unauthorized();

    var claims = new[]
    {
        new System.Security.Claims.Claim(System.Security.Claims.ClaimTypes.NameIdentifier, result.SessionId.Value.ToString()),
        new System.Security.Claims.Claim("sid", result.SessionId.Value.ToString())
    };
    var identity = new System.Security.Claims.ClaimsIdentity(claims, ServiceCollectionExtensions.BffScheme);
    await context.SignInAsync(ServiceCollectionExtensions.BffScheme, new System.Security.Claims.ClaimsPrincipal(identity));
    var csrf = antiforgery.GetAndStoreTokens(context);
    return Results.Ok(new { csrfToken = csrf.RequestToken });
});
app.MapPost("/api/auth/bff/sign-out", async (HttpContext context) =>
{
    await context.SignOutAsync(ServiceCollectionExtensions.BffScheme);
    return Results.NoContent();
});
app.Run();
public partial class Program;
