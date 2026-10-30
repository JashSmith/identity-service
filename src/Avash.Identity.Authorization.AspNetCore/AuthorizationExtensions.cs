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

    /// <summary>
    /// When true, a held permission is only granted inside the user's weekly schedule (read from the gateway by
    /// <see cref="IAccessScheduleProvider"/>); unreadable schedules deny. Set by <c>AddAvashAccessSchedules</c>.
    /// </summary>
    public bool EnforceSchedules { get; set; }
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

    /// <summary>
    /// Enforces weekly access schedules on every permission policy: requests outside the user's schedule are
    /// denied. Schedules are read from the Identity Gateway and cached per user.
    /// </summary>
    public static IServiceCollection AddAvashAccessSchedules(this IServiceCollection services,
        Action<AccessScheduleClientOptions> configure)
    {
        services.AddOptions<AccessScheduleClientOptions>().Configure(configure);
        services.PostConfigure<PermissionAuthorizationOptions>(o => o.EnforceSchedules = true);
        services.AddHttpContextAccessor();
        services.AddHttpClient(GatewayAccessScheduleProvider.HttpClientName);
        services.AddSingleton(TimeProvider.System);
        services.AddSingleton<IAccessScheduleProvider, GatewayAccessScheduleProvider>();
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
public sealed class PermissionAuthorizationHandler(
    IOptions<PermissionAuthorizationOptions>? options = null,
    IAccessScheduleProvider? schedules = null,
    TimeProvider? clock = null)
    : AuthorizationHandler<PermissionRequirement>
{
    private readonly string? _applicationId = options?.Value.ApplicationId;
    private readonly bool _enforceSchedules = options?.Value.EnforceSchedules ?? false;

    protected override async Task HandleRequirementAsync(AuthorizationHandlerContext ctx, PermissionRequirement req)
    {
        var required = PermissionNames.Qualify(_applicationId, req.Permission);
        var granted = ctx.User.FindAll("permission")
            .Concat(ctx.User.FindAll("permissions"))
            .Any(c => string.Equals(c.Value, required, StringComparison.Ordinal));
        if (!granted) return;

        if (_enforceSchedules)
        {
            // Fail closed: without a readable schedule the permission is not granted.
            var snapshot = schedules is null ? null : await schedules.GetAsync(ctx.User, CancellationToken.None);
            if (snapshot is null || !snapshot.Allows(required, (clock ?? TimeProvider.System).GetUtcNow())) return;
        }
        ctx.Succeed(req);
    }
}
