using Company.Identity.Authorization;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;

namespace Company.Identity.Authorization.AspNetCore;

public static class AuthorizationExtensions
{
    public static IServiceCollection AddCompanyAuthorization(this IServiceCollection services)
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
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext ctx, PermissionRequirement req)
    {
        var permissions = ctx.User.FindAll("permission")
            .Concat(ctx.User.FindAll("permissions"))
            .Select(x => x.Value).ToList();
        
        if (permissions.Contains(req.Permission, StringComparer.Ordinal) ||
            ctx.User.IsInRole(req.Permission)) ctx.Succeed(req);
        return Task.CompletedTask;
    }
}