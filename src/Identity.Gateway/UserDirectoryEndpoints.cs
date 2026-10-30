#pragma warning disable ASPDEPR002
using Identity.Application;
using Identity.Contracts;
using Identity.Gateway.Errors;

namespace Identity.Gateway;

public static class UserDirectoryEndpoints
{
    public static RouteGroupBuilder MapUsers(this IEndpointRouteBuilder app)
    {
        var g = app.MapGroup("/api/identity").WithTags("Users", "Roles", "Permissions");

        g.MapGet("/users", async (string? search, int? page, int? pageSize, bool? includeSessions, IUserDirectory dir,
                DelegationGuard delegation, CancellationToken ct) =>
            {
                var users = await dir.GetUsersAsync(search, page ?? 1, pageSize ?? 20, includeSessions ?? false, ct);
                if (!users.IsSuccess) return users.Error!.ToProblem();
                var restricted = await delegation.IsRestrictedAsync(ct);
                if (!restricted.IsSuccess) return restricted.Error!.ToProblem();
                if (!restricted.Value) return Results.Ok(users.Value);

                // Delegated admins only see users inside their scope; the realm-wide total would leak a count.
                var visible = await delegation.FilterManageableAsync(users.Value.Items.Select(u => u.Id).ToArray(), ct);
                if (!visible.IsSuccess) return visible.Error!.ToProblem();
                var ids = visible.Value.ToHashSet(StringComparer.Ordinal);
                return Results.Ok(users.Value with { Items = users.Value.Items.Where(u => ids.Contains(u.Id)).ToArray(), Total = null });
            })
            .RequireAuthorization(IamPermissions.UsersRead)
            .WithName("ListUsers").Produces<PagedResponse<UserDto>>(200)
            .WithOpenApi(o =>
            {
                o.Summary = "List users (proxied from Keycloak)";
                return o;
            });

        g.MapGet("/users/{id}", async (string id, IUserDirectory dir, CancellationToken ct) =>
                (await dir.GetUserAsync(id, ct)).ToHttpResult(user => Results.Ok(user))).RequireAuthorization(IamPermissions.UsersRead)
            .ForManageableUser().WithName("GetUser").Produces<UserDto>(200)
            .WithOpenApi(o =>
            {
                o.Summary = "Get user by id";
                return o;
            });

        g.MapGet("/users/{id}/roles", async (string id, IUserDirectory dir, CancellationToken ct) =>
                (await dir.GetUserRolesAsync(id, ct)).ToHttpResult(roles => Results.Ok(roles)))
            .RequireAuthorization(IamPermissions.UsersRead).ForManageableUser().WithName("GetUserRoles")
            .Produces<IReadOnlyCollection<RoleDto>>(200)
            .WithOpenApi(o =>
            {
                o.Summary = "Get roles for user";
                return o;
            });

        g.MapGet("/users/{id}/permissions", async (string id, IUserDirectory dir, CancellationToken ct) =>
                (await dir.GetUserPermissionsAsync(id, ct)).ToHttpResult(permissions => Results.Ok(permissions)))
            .RequireAuthorization(IamPermissions.UsersRead).ForManageableUser().WithName("GetUserPermissions")
            .Produces<IReadOnlyCollection<PermissionDto>>(200)
            .WithOpenApi(o =>
            {
                o.Summary = "Get effective permissions for user";
                return o;
            });

        g.MapGet("/roles",
                async (string? clientId, int? page, int? pageSize, IRoleDirectory dir, CancellationToken ct) =>
                    (await dir.GetRolesAsync(clientId, page ?? 1, pageSize ?? 20, ct)).ToHttpResult(roles => Results.Ok(roles)))
            .RequireAuthorization(IamPermissions.RolesRead).WithName("ListRoles").Produces<PagedResponse<RoleDto>>(200)
            .WithOpenApi(o =>
            {
                o.Summary = "List roles";
                return o;
            });

        return g;
    }
}