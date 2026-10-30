using System.Collections.Concurrent;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;

namespace Identity.Admin.Auth;

/// <summary>Console settings (<c>Console</c> section).</summary>
public sealed class ConsoleOptions
{
    public string KeycloakBaseUrl { get; set; } = "";
    public string GatewayBaseUrl { get; set; } = "";
    public string ClientId { get; set; } = "identity-admin-console";
    public string ClientSecret { get; set; } = "";
    public List<ConsoleTenant> Tenants { get; set; } = [];
}

/// <summary>A tenant administrators can sign in to (one Keycloak realm).</summary>
public sealed class ConsoleTenant
{
    public string Id { get; set; } = "";
    public string DisplayName { get; set; } = "";
    public string Realm { get; set; } = "";
}

/// <summary>Tokens of one signed-in administrator; kept on the server, never in the browser.</summary>
public sealed record ConsoleSession(string TenantId, string AccessToken, string? RefreshToken, string? IdToken, DateTimeOffset ExpiresAt);

/// <summary>
/// Server-side token store keyed by the <c>console_sid</c> claim of the auth cookie. A restart empties it,
/// which signs everybody out (the cookie is rejected when its session is gone).
/// </summary>
public sealed class ConsoleSessionStore
{
    private readonly ConcurrentDictionary<string, ConsoleSession> _sessions = new(StringComparer.Ordinal);

    public ConsoleSession? Get(string? sessionId) => sessionId is not null && _sessions.TryGetValue(sessionId, out var s) ? s : null;
    public void Set(string sessionId, ConsoleSession session) => _sessions[sessionId] = session;
    public void Remove(string? sessionId) { if (sessionId is not null) _sessions.TryRemove(sessionId, out _); }
}

public static class ConsoleClaims
{
    public const string SessionId = "console_sid";
    public const string Tenant = "tenant";
    public const string Permission = "permission";

    public static bool Has(this ClaimsPrincipal user, string permission) =>
        user.FindAll(Permission).Any(c => string.Equals(c.Value, permission, StringComparison.Ordinal));
}

public static class ConsoleAuthentication
{
    public const string CookieScheme = CookieAuthenticationDefaults.AuthenticationScheme;

    public static string SchemeFor(string tenantId) => $"oidc-{tenantId}";

    public static IServiceCollection AddConsoleAuthentication(this IServiceCollection services, IConfiguration configuration,
        bool isDevelopment)
    {
        var options = configuration.GetSection("Console").Get<ConsoleOptions>() ?? new ConsoleOptions();
        services.Configure<ConsoleOptions>(configuration.GetSection("Console"));
        services.AddSingleton<ConsoleSessionStore>();

        var auth = services.AddAuthentication(o =>
            {
                o.DefaultScheme = CookieScheme;
                o.DefaultChallengeScheme = CookieScheme;
            })
            .AddCookie(CookieScheme, o =>
            {
                o.Cookie.Name = "avash-admin";
                o.Cookie.HttpOnly = true;
                o.Cookie.SameSite = SameSiteMode.Lax;
                o.LoginPath = "/login";
                o.ExpireTimeSpan = TimeSpan.FromHours(8);
                o.SlidingExpiration = true;
                o.Events.OnValidatePrincipal = async ctx =>
                {
                    // The tokens live on the server; without them (e.g. after a restart) the cookie is useless,
                    // so it is removed instead of being sent again with every request.
                    var store = ctx.HttpContext.RequestServices.GetRequiredService<ConsoleSessionStore>();
                    if (store.Get(ctx.Principal?.FindFirst(ConsoleClaims.SessionId)?.Value) is not null) return;
                    ctx.RejectPrincipal();
                    await ctx.HttpContext.SignOutAsync(CookieScheme);
                };
            });

        foreach (var tenant in options.Tenants)
        {
            auth.AddOpenIdConnect(SchemeFor(tenant.Id), o =>
            {
                o.Authority = $"{options.KeycloakBaseUrl.TrimEnd('/')}/realms/{tenant.Realm}";
                o.ClientId = options.ClientId;
                o.ClientSecret = options.ClientSecret;
                o.ResponseType = "code";
                o.UsePkce = true;
                o.CallbackPath = $"/signin-oidc-{tenant.Id}";
                o.SignedOutCallbackPath = $"/signout-callback-oidc-{tenant.Id}";
                o.SignInScheme = CookieScheme;
                o.SaveTokens = false;
                o.MapInboundClaims = false;
                o.GetClaimsFromUserInfoEndpoint = false;
                o.RequireHttpsMetadata = !isDevelopment;
                o.TokenValidationParameters.NameClaimType = "preferred_username";
                // Tenant realms define their own client scopes; the claims come from the client's mappers.
                o.Scope.Clear();
                o.Scope.Add("openid");
                o.Events.OnTokenValidated = ctx => StartSession(ctx, tenant.Id);
                o.Events.OnRedirectToIdentityProvider = ctx =>
                {
                    // The console is Persian: open Keycloak's sign-in page in Persian whatever the browser language.
                    ctx.ProtocolMessage.UiLocales = "fa";
                    return Task.CompletedTask;
                };
                o.Events.OnRedirectToIdentityProviderForSignOut = ctx =>
                {
                    // Keycloak ends the SSO session for this id token and returns to the console.
                    var store = ctx.HttpContext.RequestServices.GetRequiredService<ConsoleSessionStore>();
                    var session = store.Get(ctx.HttpContext.User.FindFirst(ConsoleClaims.SessionId)?.Value);
                    ctx.ProtocolMessage.IdTokenHint = session?.IdToken;
                    ctx.ProtocolMessage.ClientId = options.ClientId;
                    return Task.CompletedTask;
                };
            });
        }
        return services;
    }

    /// <summary>Keeps the tokens server-side and adds the tenant and permission claims the UI needs.</summary>
    private static Task StartSession(TokenValidatedContext ctx, string tenantId)
    {
        var response = ctx.TokenEndpointResponse;
        if (response?.AccessToken is null || ctx.Principal is null)
        {
            ctx.Fail("Keycloak returned no access token.");
            return Task.CompletedTask;
        }

        // The cookie carries only what the UI needs; the tokens stay on the server.
        var identity = new ClaimsIdentity(ctx.Principal.Identity?.AuthenticationType, "preferred_username", null);
        foreach (var type in new[] { "sub", "preferred_username", "name" })
            if (ctx.Principal.FindFirst(type) is { } claim) identity.AddClaim(new Claim(type, claim.Value));
        ctx.Principal = new ClaimsPrincipal(identity);

        var sessionId = Guid.NewGuid().ToString("N");
        var expiresIn = int.TryParse(response.ExpiresIn, out var seconds) ? seconds : 60;
        ctx.HttpContext.RequestServices.GetRequiredService<ConsoleSessionStore>().Set(sessionId, new ConsoleSession(
            tenantId, response.AccessToken, response.RefreshToken, response.IdToken, DateTimeOffset.UtcNow.AddSeconds(expiresIn)));

        identity.AddClaim(new Claim(ConsoleClaims.SessionId, sessionId));
        identity.AddClaim(new Claim(ConsoleClaims.Tenant, tenantId));
        foreach (var permission in PermissionsOf(response.AccessToken))
            identity.AddClaim(new Claim(ConsoleClaims.Permission, permission));
        return Task.CompletedTask;
    }

    /// <summary>Permissions from the access token (validated by Keycloak's token endpoint over the back channel).</summary>
    public static IEnumerable<string> PermissionsOf(string accessToken)
    {
        var token = new JwtSecurityTokenHandler().ReadJwtToken(accessToken);
        return token.Claims.Where(c => c.Type is "permissions" or "permission").Select(c => c.Value).Distinct(StringComparer.Ordinal);
    }

    /// <summary>Sign-in per tenant and sign-out (form POST with an antiforgery token).</summary>
    public static IEndpointRouteBuilder MapConsoleAuthentication(this IEndpointRouteBuilder app)
    {
        app.MapGet("/auth/login/{tenant}", (string tenant, string? returnUrl, IOptions<ConsoleOptions> options) =>
        {
            if (options.Value.Tenants.All(t => t.Id != tenant)) return Results.NotFound();
            // Only local return URLs: an open redirect would let a link send administrators elsewhere after login.
            var target = !string.IsNullOrEmpty(returnUrl) && returnUrl.StartsWith('/') && !returnUrl.StartsWith("//") ? returnUrl : "/";
            return Results.Challenge(new AuthenticationProperties { RedirectUri = target }, [SchemeFor(tenant)]);
        }).AllowAnonymous();

        app.MapPost("/auth/logout", async (HttpContext http, IAntiforgery antiforgery, ConsoleSessionStore store) =>
        {
            await antiforgery.ValidateRequestAsync(http);
            var tenant = http.User.FindFirst(ConsoleClaims.Tenant)?.Value;
            var properties = new AuthenticationProperties { RedirectUri = "/login" };
            var result = tenant is null
                ? Results.SignOut(properties, [CookieScheme])
                : Results.SignOut(properties, [CookieScheme, SchemeFor(tenant)]);
            // The OIDC handler reads the id token while redirecting, so the session is removed afterwards.
            http.Response.OnCompleted(() =>
            {
                store.Remove(http.User.FindFirst(ConsoleClaims.SessionId)?.Value);
                return Task.CompletedTask;
            });
            return result;
        }).RequireAuthorization();

        return app;
    }
}
