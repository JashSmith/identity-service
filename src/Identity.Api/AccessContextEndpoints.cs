#pragma warning disable ASPDEPR002
using Identity.Application;
using Identity.Contracts;

namespace Identity.Api;

public static class AccessContextEndpoints
{
    public static RouteGroupBuilder MapAccessContext(this IEndpointRouteBuilder app)
    {
        var g = app.MapGroup("/api/identity").WithTags("Access");
        g.MapGet("/access-context", async (ICurrentUserContext current, IUserDirectory dirs, IScopedAccessStore store, CancellationToken ct) =>
            {
                if (current.UserId is null) return Results.Unauthorized();
                var perms = await dirs.GetUserPermissionsAsync(current.UserId, ct);
                var doc = await store.GetAsync(current.UserId, ct);
                var resp = new AccessContextResponse(
                    current.UserId, current.Username,
                    perms.Select(p => p.Name).OrderBy(x => x, StringComparer.Ordinal).ToArray(),
                    doc.Assignments.ToArray());
                return Results.Ok(resp);
            }).RequireAuthorization()
            .WithName("GetAccessContext")
            .Produces<AccessContextResponse>(200)
            .WithOpenApi(o => { o.Summary = "Current user's permissions + scoped assignments (facade resolution for large tokens)"; return o; });
        return g;
    }
}
