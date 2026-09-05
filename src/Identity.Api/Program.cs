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
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);
var authority = builder.Configuration["Identity:Tokens:Issuer"] ?? "https://localhost:7001";
var audience = builder.Configuration["Identity:Tokens:Audience"] ?? "identity-api";
var signingKeys = new JwtSigningKeyProvider(builder.Configuration);
builder.Services.AddSingleton(signingKeys);
builder.Services.AddIdentityPersistence(builder.Configuration.GetConnectionString("Identity") ?? "Data Source=identity.db", useSqlite: true);
builder.Services.AddScoped<LocalAuthenticationService>();
builder.Services.AddSingleton<ISystemClock>(_ => new SystemClock(TimeProvider.System));
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
    SigningKey = signingKeys.Key
});
builder.Services.AddCompanyAuthorization();
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
        var clock = scope.ServiceProvider.GetRequiredService<ISystemClock>();
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
    var parameters = keys.PublicKey.Rsa!.ExportParameters(false);
    return Results.Ok(new
    {
        keys = new[]
        {
            new
            {
                kty = "RSA",
                use = "sig",
                alg = "RS256",
                kid = keys.KeyId,
                n = Base64UrlEncoder.Encode(parameters.Modulus!),
                e = Base64UrlEncoder.Encode(parameters.Exponent!)
            }
        }
    });
});
app.MapGrpcService<IdentityGrpcService>();
app.MapGet("/api/users/me", (HttpContext context) =>
{
    if (context.User.Identity?.IsAuthenticated != true) return Results.Unauthorized();
    var claims = context.User.Claims.ToArray();
    return Results.Ok(new UserResponse(Guid.TryParse(context.User.FindFirst("sub")?.Value, out var id) ? id : Guid.Empty, context.User.Identity.Name ?? string.Empty, context.User.FindFirst("name")?.Value ?? context.User.Identity.Name ?? string.Empty, claims.Where(x => x.Type is "role" or "roles").Select(x => x.Value).ToArray(), claims.Where(x => x.Type is "permission" or "permissions").Select(x => x.Value).ToArray(), Guid.TryParse(context.User.FindFirst("sid")?.Value, out var sid) ? sid : null));
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
app.MapPost("/api/auth/antiforgery", (HttpContext context, IAntiforgery antiforgery) =>
{
    var tokens = antiforgery.GetAndStoreTokens(context);
    return Results.Ok(new { token = tokens.RequestToken });
});
app.Run();
public partial class Program;
