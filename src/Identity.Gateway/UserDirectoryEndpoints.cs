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

        g.MapGet("/users", async (string? search, int? page, int? pageSize, bool? includeSessions, IUserDirectory dir, CancellationToken ct) =>
                (await dir.GetUsersAsync(search, page ?? 1, pageSize ?? 20, includeSessions ?? false, ct))
                .ToHttpResult(users => Results.Ok(users)))
            .RequireAuthorization("Identity.Users.Read")
            .WithName("ListUsers").Produces<PagedResponse<UserDto>>(200)
            .WithOpenApi(o =>
            {
                o.Summary = "List users (proxied from Keycloak)";
                return o;
            });

        g.MapGet("/users/{id}", async (string id, IUserDirectory dir, CancellationToken ct) =>
                (await dir.GetUserAsync(id, ct)).ToHttpResult(user => Results.Ok(user))).RequireAuthorization("Identity.Users.Read").WithName("GetUser").Produces<UserDto>(200)
            .WithOpenApi(o =>
            {
                o.Summary = "Get user by id";
                return o;
            });

        g.MapGet("/users/{id}/roles", async (string id, IUserDirectory dir, CancellationToken ct) =>
                (await dir.GetUserRolesAsync(id, ct)).ToHttpResult(roles => Results.Ok(roles)))
            .RequireAuthorization("Identity.Users.Read").WithName("GetUserRoles")
            .Produces<IReadOnlyCollection<RoleDto>>(200)
            .WithOpenApi(o =>
            {
                o.Summary = "Get roles for user";
                return o;
            });

        g.MapGet("/users/{id}/permissions", async (string id, IUserDirectory dir, CancellationToken ct) =>
                (await dir.GetUserPermissionsAsync(id, ct)).ToHttpResult(permissions => Results.Ok(permissions)))
            .RequireAuthorization("Identity.Users.Read").WithName("GetUserPermissions")
            .Produces<IReadOnlyCollection<PermissionDto>>(200)
            .WithOpenApi(o =>
            {
                o.Summary = "Get effective permissions for user";
                return o;
            });

        g.MapGet("/roles",
                async (string? clientId, int? page, int? pageSize, IRoleDirectory dir, CancellationToken ct) =>
                    (await dir.GetRolesAsync(clientId, page ?? 1, pageSize ?? 20, ct)).ToHttpResult(roles => Results.Ok(roles)))
            .RequireAuthorization("Identity.Roles.Read").WithName("ListRoles").Produces<PagedResponse<RoleDto>>(200)
            .WithOpenApi(o =>
            {
                o.Summary = "List roles";
                return o;
            });

        // IPermissionRegistry passthrough for permission catalog if available
        g.MapGet("/permissions",
                async (string? serviceId, bool? includeDeprecated, IPermissionRegistry reg, CancellationToken ct) =>
                    Results.Ok(await reg.GetPermissionsAsync(serviceId, includeDeprecated ?? false, ct)))
            .RequireAuthorization("Identity.Permissions.Read").WithName("ListPermissions")
            .WithOpenApi(o =>
            {
                o.Summary = "List registered permissions";
                return o;
            });

        return g;
    }
}