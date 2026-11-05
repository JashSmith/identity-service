#pragma warning disable ASPDEPR002
using Identity.Application;
using Identity.Application.Scope;
using Identity.Contracts;
using Identity.Gateway.Errors;

namespace Identity.Gateway;

public static class AccessContextEndpoints
{
    public static RouteGroupBuilder MapAccessContext(this IEndpointRouteBuilder app)
    {
        var g = app.MapGroup("/api/identity").WithTags("Access");
        g.MapGet("/access-context", async (ICurrentUserContext current, IUserDirectory dirs, IUserScopeReader scopes, CancellationToken ct) =>
            {
                if (current.UserId is null) return Results.Unauthorized();
                var perms = await dirs.GetUserPermissionsAsync(current.UserId, ct);
                if (!perms.IsSuccess) return perms.Error!.ToProblem();
                // Keycloak is the single source of truth: effective scopes = group ∪ user attributes.
                var doc = await scopes.GetAsync(current.UserId, ct);
                if (!doc.IsSuccess) return doc.Error!.ToProblem();
                var effectiveScopes = await scopes.GetEffectiveAsync(current.UserId, ct);
                if (!effectiveScopes.IsSuccess) return effectiveScopes.Error!.ToProblem();
                var resp = new AccessContextResponse(
                    current.UserId, current.Username,
                    perms.Value.Select(p => p.Name).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(x => x, StringComparer.Ordinal).ToArray(),
                    doc.Value.Assignments.ToArray(),
                    effectiveScopes.Value);
                return Results.Ok(resp);
            }).RequireAuthorization()
            .WithName("GetAccessContext")
            .Produces<AccessContextResponse>(200)
            .WithOpenApi(o => { o.Summary = "Current user's permissions + scoped assignments (Keycloak attributes, group ∪ user)"; return o; });
        return g;
    }
}
