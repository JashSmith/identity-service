#pragma warning disable ASPDEPR002
using Identity.Application;
using Identity.Contracts;
using Identity.Gateway.Errors;

namespace Identity.Gateway;

public static class UserDirectoryEndpoints
{
    /// <summary>A delegated admin's user list scans at most this many Keycloak users (search narrows it).</summary>
    private const int DelegatedScanPageSize = 100;
    private const int DelegatedScanPages = 20;

    public static RouteGroupBuilder MapUsers(this IEndpointRouteBuilder app)
    {
        var g = app.MapGroup("/api/identity").WithTags("Users", "Roles", "Permissions");

        g.MapGet("/users", async (string? search, int? page, int? pageSize, bool? includeSessions, IUserDirectory dir,
                DelegationGuard delegation, CancellationToken ct) =>
            {
                var restricted = await delegation.IsRestrictedAsync(ct);
                if (!restricted.IsSuccess) return restricted.Error!.ToProblem();
                if (!restricted.Value)
                    return (await dir.GetUsersAsync(search, page ?? 1, pageSize ?? 20, includeSessions ?? false, ct))
                        .ToHttpResult(users => Results.Ok(users));

                // Delegated admins only see users inside their scope. Keycloak cannot filter by the merged scope
                // view, so the matching users are scanned (up to a cap), filtered, and then paged; the total is
                // the number of visible users, never the realm's.
                var visible = new List<UserDto>();
                for (var scanPage = 1; scanPage <= DelegatedScanPages; scanPage++)
                {
                    var batch = await dir.GetUsersAsync(search, scanPage, DelegatedScanPageSize, false, ct);
                    if (!batch.IsSuccess) return batch.Error!.ToProblem();
                    var manageable = await delegation.FilterManageableAsync(batch.Value.Items.Select(u => u.Id).ToArray(), ct);
                    if (!manageable.IsSuccess) return manageable.Error!.ToProblem();
                    var ids = manageable.Value.ToHashSet(StringComparer.Ordinal);
                    visible.AddRange(batch.Value.Items.Where(u => ids.Contains(u.Id)));
                    if (batch.Value.Items.Count < DelegatedScanPageSize) break;
                }

                var size = Math.Clamp(pageSize ?? 20, 1, DelegatedScanPageSize);
                var number = Math.Max(1, page ?? 1);
                return Results.Ok(new PagedResponse<UserDto>(visible.Skip((number - 1) * size).Take(size).ToArray(), number, size, visible.Count));
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