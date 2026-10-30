using Avash.Identity.Authorization;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Avash.Identity.Authorization.AspNetCore;

/// <summary>Options of the permission policies.</summary>
public sealed class PermissionAuthorizationOptions
{
    /// <summary>
    /// This service's application (Keycloak client) id. Policies named with a local permission
    /// (<c>Module:Resource:Action</c>) are matched against <c>{ApplicationId}:Module:Resource:Action</c> in the token.
    /// </summary>
    public string? ApplicationId { get; set; }
}

public static class AuthorizationExtensions
{
    /// <summary>
    /// Every authorization policy name is treated as a permission: the request is allowed when the token's
    /// <c>permissions</c> claim contains it (qualified with <see cref="PermissionAuthorizationOptions.ApplicationId"/>
    /// when the name is local).
    /// </summary>
    public static IServiceCollection AddAvashAuthorization(this IServiceCollection services,
        Action<PermissionAuthorizationOptions>? configure = null)
    {
        services.AddOptions<PermissionAuthorizationOptions>().Configure(o => configure?.Invoke(o));
        services.AddSingleton<IAuthorizationPolicyProvider, PermissionPolicyProvider>();
        services.AddSingleton<IAuthorizationHandler, PermissionAuthorizationHandler>();
        services.AddAuthorization();
        return services;
    }
}

public sealed class PermissionPolicyProvider(IOptions<AuthorizationOptions> options)
    : DefaultAuthorizationPolicyProvider(options)
{
    public override async Task<AuthorizationPolicy?> GetPolicyAsync(string policyName) =>
        await base.GetPolicyAsync(policyName) ?? new AuthorizationPolicyBuilder()
            .RequireAuthenticatedUser()
            .AddRequirements(new PermissionRequirement(policyName))
            .Build();
}

/// <summary>
/// Only explicit permission claims count. Roles, including Keycloak's realm-admin, are not permissions.
/// Names are compared exactly (they follow one scheme: <c>{application}:{Module}:{Resource}:{Action}</c>).
/// </summary>
public sealed class PermissionAuthorizationHandler(IOptions<PermissionAuthorizationOptions>? options = null)
    : AuthorizationHandler<PermissionRequirement>
{
    private readonly string? _applicationId = options?.Value.ApplicationId;

    protected override Task HandleRequirementAsync(AuthorizationHandlerContext ctx, PermissionRequirement req)
    {
        var required = PermissionNames.Qualify(_applicationId, req.Permission);
        var granted = ctx.User.FindAll("permission")
            .Concat(ctx.User.FindAll("permissions"))
            .Any(c => string.Equals(c.Value, required, StringComparison.Ordinal));

        if (granted)
        {
            ctx.Succeed(req);
        }
        return Task.CompletedTask;
    }
}
