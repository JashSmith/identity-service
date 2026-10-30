using Avash.Identity.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Avash.Identity.Authorization.AspNetCore;

public static class AccessContextExtensions
{
    /// <summary>
    /// Registers <see cref="ICurrentAccessContext"/> as scoped. When <c>Identity:AccessContext:GatewayBaseUrl</c>
    /// is configured (or the overload with <paramref name="configure"/> is used), scoped assignments are resolved
    /// from the Identity Gateway when the <c>iam_access</c> claim is absent/oversized (call <c>EnsureLoadedAsync</c>);
    /// otherwise the claims-only context is used.
    /// </summary>
    public static IServiceCollection AddAvashAccessContext(this IServiceCollection services)
    {
        services.Configure<AccessContextOptions>(_ => { });
        return services.AddAvashAccessContextCore();
    }

    /// <summary>
    /// Variant that lets the caller configure <see cref="AccessContextOptions"/> inline, e.g.
    /// <c>services.AddAvashAccessContext(o =&gt; o.GatewayBaseUrl = configuration["Identity:Server"])</c>.
    /// </summary>
    public static IServiceCollection AddAvashAccessContext(
        this IServiceCollection services,
        Action<AccessContextOptions> configure)
    {
        services.Configure(configure);
        return services.AddAvashAccessContextCore();
    }

    private static IServiceCollection AddAvashAccessContextCore(this IServiceCollection services)
    {
        services.AddHttpContextAccessor();
        services.AddHttpClient("IdentityAccessContext");
        services.AddScoped<ICurrentAccessContext>(sp =>
        {
            var accessor = sp.GetRequiredService<IHttpContextAccessor>();
            var principal = accessor.HttpContext?.User ?? new System.Security.Claims.ClaimsPrincipal();
            var opts = sp.GetRequiredService<IOptions<AccessContextOptions>>();
            if (string.IsNullOrWhiteSpace(opts.Value.GatewayBaseUrl))
                return new ClaimsPrincipalAccessContext(principal);
            var factory = sp.GetRequiredService<IHttpClientFactory>();
            return new GatewayResolvingAccessContext(principal, accessor, factory, opts,
                sp.GetService<Microsoft.Extensions.Logging.ILogger<GatewayResolvingAccessContext>>());
        });
        return services;
    }
}
