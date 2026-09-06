using Company.Identity.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace Company.Identity.Authentication.AspNetCore;

public static class ServiceCollectionExtensions
{
    public const string BffScheme = "CompanyIdentityBff";
    public const string BffPolicyScheme = "CompanyIdentityBffOrBearer";
    private const string BffCookieName = "__Host-company-identity";

    public static IServiceCollection AddCompanyAuthentication(this IServiceCollection services, IdentityAuthenticationOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        services.AddAuthentication(authentication =>
        {
            authentication.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            authentication.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        })
        .AddCookie(BffScheme, cookie =>
        {
            cookie.Cookie.Name = BffCookieName;
            cookie.Cookie.HttpOnly = true;
            cookie.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            cookie.Cookie.SameSite = SameSiteMode.Lax;
            cookie.SlidingExpiration = false;
            cookie.ExpireTimeSpan = TimeSpan.FromHours(8);
            cookie.Events.OnRedirectToLogin = context =>
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return Task.CompletedTask;
            };
            cookie.Events.OnRedirectToAccessDenied = context =>
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                return Task.CompletedTask;
            };
            cookie.Events.OnValidatePrincipal = async context =>
            {
                var sessionId = context.Principal?.FindFirst("sid")?.Value;
                var validator = context.HttpContext.RequestServices.GetService<IBffSessionValidator>();
                if (validator is null || string.IsNullOrWhiteSpace(sessionId) ||
                    !await validator.ValidateAsync(sessionId, context.HttpContext.RequestAborted))
                {
                    context.RejectPrincipal();
                }
            };
        })
        .AddJwtBearer(jwt =>
        {
            jwt.Authority = options.Authority;
            jwt.RequireHttpsMetadata = options.RequireHttpsMetadata;
            jwt.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = options.Audiences.Length > 0,
                ValidAudiences = options.Audiences,
                ValidateLifetime = true,
                ClockSkew = options.ClockSkew,
                IssuerSigningKey = options.SigningKey,
                IssuerSigningKeys = options.SigningKeys.Count > 0 ? options.SigningKeys : null,
                ValidateIssuerSigningKey = options.SigningKey is not null || options.SigningKeys.Count > 0,
                ValidIssuer = options.SigningKey is not null || options.SigningKeys.Count > 0 ? options.Authority : null
            };
        });
        return services;
    }

    public static IServiceCollection AddCompanyBffSessions(this IServiceCollection services)
    {
        services.AddAuthentication(authentication =>
        {
            authentication.DefaultAuthenticateScheme = BffPolicyScheme;
            authentication.DefaultChallengeScheme = BffPolicyScheme;
        })
        .AddPolicyScheme(BffPolicyScheme, displayName: null, policy =>
        {
            policy.ForwardDefaultSelector = context =>
            {
                var authorization = context.Request.Headers.Authorization.ToString();
                if (authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                    return JwtBearerDefaults.AuthenticationScheme;

                return context.Request.Cookies.ContainsKey(BffCookieName)
                    ? BffScheme
                    : JwtBearerDefaults.AuthenticationScheme;
            };
        });

        services.AddAntiforgery(options =>
        {
            options.Cookie.Name = "__Host-company-identity-csrf";
            options.Cookie.HttpOnly = false;
            options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            options.Cookie.SameSite = SameSiteMode.Strict;
            options.HeaderName = "X-CSRF-TOKEN";
        });
        return services;
    }
}
