using Company.Identity.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Company.Identity.Authorization.AspNetCore;

public static class AccessContextExtensions
{
    /// <summary>
    /// Registers <see cref="ICurrentAccessContext"/> as scoped. When <c>Identity:AccessContext:FacadeBaseUrl</c>
    /// is configured (or the overload with <paramref name="configure"/> is used), scoped assignments are resolved
    /// from the Identity Facade when the <c>iam_access</c> claim is absent/oversized (call <c>EnsureLoadedAsync</c>);
    /// otherwise the claims-only context is used.
    /// </summary>
    public static IServiceCollection AddCompanyAccessContext(this IServiceCollection services)
    {
        services.Configure<AccessContextOptions>(_ => { });
        return services.AddCompanyAccessContextCore();
    }

    /// <summary>
    /// Variant that lets the caller configure <see cref="AccessContextOptions"/> inline, e.g.
    /// <c>services.AddCompanyAccessContext(o =&gt; o.FacadeBaseUrl = configuration["Identity:Server"])</c>.
    /// </summary>
    public static IServiceCollection AddCompanyAccessContext(
        this IServiceCollection services,
        Action<AccessContextOptions> configure)
    {
        services.Configure(configure);
        return services.AddCompanyAccessContextCore();
    }

    private static IServiceCollection AddCompanyAccessContextCore(this IServiceCollection services)
    {
        services.AddHttpContextAccessor();
        services.AddHttpClient("IdentityAccessContext");
        services.AddScoped<ICurrentAccessContext>(sp =>
        {
            var accessor = sp.GetRequiredService<IHttpContextAccessor>();
            var principal = accessor.HttpContext?.User ?? new System.Security.Claims.ClaimsPrincipal();
            var opts = sp.GetRequiredService<IOptions<AccessContextOptions>>();
            if (string.IsNullOrWhiteSpace(opts.Value.FacadeBaseUrl))
                return new ClaimsPrincipalAccessContext(principal);
            var factory = sp.GetRequiredService<IHttpClientFactory>();
            return new FacadeResolvingAccessContext(principal, accessor, factory, opts);
        });
        return services;
    }
}
