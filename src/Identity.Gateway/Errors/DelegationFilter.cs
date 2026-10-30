using Identity.Application;

namespace Identity.Gateway.Errors;

/// <summary>
/// Answers 403 before the handler runs when the user in the <c>{id}</c> route value is outside the
/// scope of a delegated administrator (see <see cref="DelegationGuard"/>).
/// </summary>
public sealed class DelegationFilter : IEndpointFilter
{
    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        if (context.HttpContext.GetRouteValue("id") is not string userId) return await next(context);

        var guard = context.HttpContext.RequestServices.GetRequiredService<DelegationGuard>();
        var allowed = await guard.EnsureCanManageUserAsync(userId, context.HttpContext.RequestAborted);
        return allowed.IsSuccess ? await next(context) : allowed.Error!.ToProblem();
    }
}

public static class DelegationFilterExtensions
{
    /// <summary>Restricts the endpoint to users the current administrator may manage.</summary>
    public static RouteHandlerBuilder ForManageableUser(this RouteHandlerBuilder builder) =>
        builder.AddEndpointFilter<DelegationFilter>().ProducesProblem(403);
}
