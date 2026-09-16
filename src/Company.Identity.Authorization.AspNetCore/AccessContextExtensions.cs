using Company.Identity.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Company.Identity.Authorization.AspNetCore;

public static class AccessContextExtensions
{
    public static IServiceCollection AddCompanyAccessContext(this IServiceCollection services)
    {
        services.AddHttpContextAccessor();
        services.AddScoped<ICurrentAccessContext>(sp =>
        {
            var accessor = sp.GetRequiredService<IHttpContextAccessor>();
            var principal = accessor.HttpContext?.User ?? new System.Security.Claims.ClaimsPrincipal();
            return new ClaimsPrincipalAccessContext(principal);
        });
        return services;
    }
}
