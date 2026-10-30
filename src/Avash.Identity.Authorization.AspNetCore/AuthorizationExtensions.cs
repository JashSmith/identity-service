using Avash.Identity.Authorization;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;

namespace Avash.Identity.Authorization.AspNetCore;

public static class AuthorizationExtensions
{
    public static IServiceCollection AddAvashAuthorization(this IServiceCollection services)
    {
        services.AddSingleton<IAuthorizationPolicyProvider, PermissionPolicyProvider>();
        services.AddSingleton<IAuthorizationHandler, PermissionAuthorizationHandler>();
        services.AddAuthorization();
        return services;
    }
}

public sealed class PermissionPolicyProvider(Microsoft.Extensions.Options.IOptions<AuthorizationOptions> options)
    : DefaultAuthorizationPolicyProvider(options)
{
    public override async Task<AuthorizationPolicy?> GetPolicyAsync(string policyName) =>
        await base.GetPolicyAsync(policyName) ?? new AuthorizationPolicyBuilder()
            .RequireAuthenticatedUser()
            .AddRequirements(new PermissionRequirement(policyName))
            .Build();
}

public sealed class PermissionAuthorizationHandler : AuthorizationHandler<PermissionRequirement>
{
    // Only explicit permission claims count. Roles, including Keycloak's realm-admin, are not
    // permissions: treating them as such let any realm administrator pass every policy.
    // Matching stays case-insensitive until permission naming is unified.
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext ctx, PermissionRequirement req)
    {
        var granted = ctx.User.FindAll("permission")
            .Concat(ctx.User.FindAll("permissions"))
            .Any(c => string.Equals(c.Value, req.Permission, StringComparison.OrdinalIgnoreCase));

        if (granted)
        {
            ctx.Succeed(req);
        }
        return Task.CompletedTask;
    }
}