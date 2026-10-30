using Avash.Identity.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace Avash.Identity.Authentication.AspNetCore;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddAvashAuthentication(this IServiceCollection services,
        Action<IdentityAuthenticationOptions> configure)
    {
        var options = new IdentityAuthenticationOptions();
        configure(options);
        if (string.IsNullOrWhiteSpace(options.Authority))
            throw new InvalidOperationException("Identity authority is required.");
        var audiences = options.Audiences.Length > 0 ? options.Audiences :
            string.IsNullOrWhiteSpace(options.Audience) ? [] : [options.Audience];
        var additional = options.AdditionalAuthorities.Where(a => !string.IsNullOrWhiteSpace(a))
            .Select(a => a.TrimEnd('/')).Distinct(StringComparer.Ordinal).ToArray();
        if (additional.Length == 0)
        {
            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(jwt => ConfigureJwtBearer(jwt, options, options.Authority, audiences));
            return services;
        }

        // Several issuers (one realm per tenant): "Bearer" forwards to the scheme of the token's issuer.
        // The issuer is only peeked at here; the chosen scheme validates it (and the signature) strictly.
        var authorities = new[] { options.Authority.TrimEnd('/') }.Concat(additional).ToArray();
        var schemes = authorities.Select((a, i) => (Authority: a, Scheme: $"{JwtBearerDefaults.AuthenticationScheme}:{i}")).ToArray();
        var builder = services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddPolicyScheme(JwtBearerDefaults.AuthenticationScheme, "Bearer (per issuer)", policy =>
                policy.ForwardDefaultSelector = http =>
                {
                    var issuer = PeekIssuer(http.Request.Headers.Authorization.ToString());
                    return schemes.FirstOrDefault(s => string.Equals(s.Authority, issuer, StringComparison.Ordinal)).Scheme
                           ?? schemes[0].Scheme;
                });
        foreach (var (authority, scheme) in schemes)
            builder.AddJwtBearer(scheme, jwt => ConfigureJwtBearer(jwt, options, authority, audiences, strictIssuer: true));
        return services;
    }

    private static string? PeekIssuer(string authorization)
    {
        const string prefix = "Bearer ";
        if (!authorization.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) return null;
        var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
        var token = authorization[prefix.Length..].Trim();
        return handler.CanReadToken(token) ? handler.ReadJwtToken(token).Issuer?.TrimEnd('/') : null;
    }

    private static void ConfigureJwtBearer(JwtBearerOptions jwt, IdentityAuthenticationOptions options, string authority,
        string[] audiences, bool strictIssuer = false)
    {
        {
            jwt.Authority = authority.TrimEnd('/');
            jwt.RequireHttpsMetadata = options.RequireHttpsMetadata;
            jwt.RefreshOnIssuerKeyNotFound = true;
            // Keycloak-centric gateway: keep OIDC claim names as issued ("sub", "preferred_username",
            // "sid", "permissions") instead of letting the handler rewrite them to SOAP claim types.
            jwt.MapInboundClaims = false;
            // With AcceptIssuerFromDiscovery, ValidIssuer stays unset so the JwtBearer
            // post-configure fills it from the discovery document's "issuer" claim —
            // the gateway-proxied Keycloak issuer, not the gateway URL itself.
            jwt.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = options.AcceptIssuerFromDiscovery && !strictIssuer ? null : authority.TrimEnd('/'),
                ValidateAudience = audiences.Length > 0, ValidAudiences = audiences,
                ValidateLifetime = true, ValidateIssuerSigningKey = true,
                ClockSkew = options.ClockSkew, ValidAlgorithms = options.ValidAlgorithms
            };
            jwt.Events = new JwtBearerEvents
            {
                OnAuthenticationFailed = ctx =>
                {
                    // Never log the token: a captured log line would be a usable credential.
                    ctx.HttpContext.RequestServices.GetService<ILoggerFactory>()?
                        .CreateLogger("Avash.Identity.Authentication")
                        .LogDebug("Bearer token rejected: {Reason}", ctx.Exception.GetType().Name);
                    return Task.CompletedTask;
                },
                OnTokenValidated = context =>
                {
                    if (!options.ValidateTokenType ||
                        context.SecurityToken is not System.IdentityModel.Tokens.Jwt.JwtSecurityToken token)
                        return Task.CompletedTask;
                    if (token.Header.TryGetValue("typ", out var value) && value is string type &&
                        !string.Equals(type, "Bearer", StringComparison.OrdinalIgnoreCase) &&
                        !string.Equals(type, "at+jwt", StringComparison.OrdinalIgnoreCase))
                        context.Fail("Unexpected token type.");
                    return Task.CompletedTask;
                }
            };
        }
    }
}