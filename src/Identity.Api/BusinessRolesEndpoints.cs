#pragma warning disable ASPDEPR002
using Company.Identity.Abstractions;
using Identity.Application;
using Identity.Contracts;

namespace Identity.Api;

public static class BusinessRolesEndpoints
{
    public static RouteGroupBuilder MapBusinessRoles(this IEndpointRouteBuilder app)
    {
        var g = app.MapGroup("/api/identity/business-roles").WithTags("Business Roles");

        g.MapGet("", async (IBusinessRoleStore store, CancellationToken ct) =>
                Results.Ok(await store.ListAsync(ct)))
            .RequireAuthorization(IamPermissions.RolesRead)
            .WithName("ListBusinessRoles")
            .Produces<IReadOnlyCollection<BusinessRoleDto>>(200)
            .WithOpenApi(o => { o.Summary = "List business (composite) roles"; return o; });

        g.MapGet("/{name}", async (string name, IBusinessRoleStore store, CancellationToken ct) =>
            {
                var dto = await store.GetAsync(name, ct);
                return dto is null
                    ? Results.NotFound(new ProblemResponse("not_found", $"business role '{name}' not found", Guid.NewGuid().ToString("N")))
                    : Results.Ok(dto);
            }).RequireAuthorization(IamPermissions.RolesRead)
            .WithName("GetBusinessRole")
            .Produces<BusinessRoleDto>(200);

        g.MapGet("/{name}/effective-permissions",
                async (string name, IBusinessRoleStore store, CancellationToken ct) =>
                {
                    var dto = await store.GetAsync(name, ct);
                    if (dto is null) return Results.NotFound(new ProblemResponse("not_found", $"business role '{name}' not found", Guid.NewGuid().ToString("N")));
                    var perms = await store.GetEffectivePermissionsAsync(name, ct);
                    return Results.Ok(new EffectivePermissionsResponse(name, perms));
                }).RequireAuthorization(IamPermissions.RolesRead)
            .WithName("GetEffectivePermissions")
            .Produces<EffectivePermissionsResponse>(200);

        g.MapPost("", async (CreateBusinessRoleRequest req, ProvisioningOrchestrator orch,
                Identity.Application.Scope.IScopeCacheInvalidator scopeCache, CancellationToken ct) =>
            {
                if (string.IsNullOrWhiteSpace(req.Name))
                    return Results.BadRequest(new ProblemResponse("validation_error", "name is required", Guid.NewGuid().ToString("N")));
                try
                {
                    var dto = await orch.CreateBusinessRoleAsync(req.Name, req.Description, req.Permissions ?? Array.Empty<string>(), ct);
                    scopeCache.Invalidate();
                    return Results.Created($"/api/identity/business-roles/{Uri.EscapeDataString(dto.Name)}", dto);
                }
                catch (InvalidOperationException ex) when (ex.Message.Contains("already exists", StringComparison.OrdinalIgnoreCase))
                {
                    return Results.Conflict(new ProblemResponse("conflict", ex.Message, Guid.NewGuid().ToString("N")));
                }
                catch (InvalidOperationException ex)
                {
                    return Results.BadRequest(new ProblemResponse("validation_error", ex.Message, Guid.NewGuid().ToString("N")));
                }
            }).RequireAuthorization(IamPermissions.RolesManage)
            .WithName("CreateBusinessRole")
            .Produces<BusinessRoleDto>(201).Produces<ProblemResponse>(400).Produces<ProblemResponse>(409);

        g.MapPut("/{name}", async (string name, UpdateBusinessRoleRequest req, IBusinessRoleStore store,
                Identity.Application.Scope.IScopeCacheInvalidator scopeCache, CancellationToken ct) =>
            {
                var dto = await store.UpdateAsync(name, req.Description, ct);
                if (dto is not null) scopeCache.Invalidate();
                return dto is null
                    ? Results.NotFound(new ProblemResponse("not_found", $"business role '{name}' not found", Guid.NewGuid().ToString("N")))
                    : Results.Ok(dto);
            }).RequireAuthorization(IamPermissions.RolesManage)
            .WithName("UpdateBusinessRole")
            .Produces<BusinessRoleDto>(200);

        g.MapDelete("/{name}", async (string name, ProvisioningOrchestrator orch,
                Identity.Application.Scope.IScopeCacheInvalidator scopeCache, CancellationToken ct) =>
            {
                try
                {
                    var ok = await orch.DeleteBusinessRoleSafeAsync(name, ct);
                    if (ok) scopeCache.Invalidate();
                    return ok ? Results.NoContent()
                        : Results.NotFound(new ProblemResponse("not_found", $"business role '{name}' not found", Guid.NewGuid().ToString("N")));
                }
                catch (InvalidOperationException ex)
                {
                    return Results.BadRequest(new ProblemResponse("validation_error", ex.Message, Guid.NewGuid().ToString("N")));
                }
            }).RequireAuthorization(IamPermissions.RolesManage)
            .WithName("DeleteBusinessRole")
            .Produces(204).Produces<ProblemResponse>(400);

        g.MapPost("/{name}/permissions", async (string name, AssignPermissionsRequest req, IBusinessRoleStore store, IPermissionRegistry perms,
                Identity.Application.Scope.IScopeCacheInvalidator scopeCache, CancellationToken ct) =>
            {
                if (req.Permissions is null || req.Permissions.Count == 0)
                    return Results.BadRequest(new ProblemResponse("validation_error", "permissions are required", Guid.NewGuid().ToString("N")));
                var all = await perms.GetPermissionsAsync(null, true, ct);
                foreach (var p in req.Permissions)
                    if (!all.Any(x => string.Equals(x.Name, p, StringComparison.Ordinal)))
                        return Results.BadRequest(new ProblemResponse("validation_error", $"Permission '{p}' does not exist.", Guid.NewGuid().ToString("N")));
                try
                {
                    await store.AddPermissionsAsync(name, req.Permissions, ct);
                    scopeCache.Invalidate();
                    var dto = await store.GetAsync(name, ct);
                    return dto is null
                        ? Results.NotFound(new ProblemResponse("not_found", $"business role '{name}' not found", Guid.NewGuid().ToString("N")))
                        : Results.Ok(dto);
                }
                catch (InvalidOperationException ex)
                {
                    return Results.BadRequest(new ProblemResponse("validation_error", ex.Message, Guid.NewGuid().ToString("N")));
                }
            }).RequireAuthorization(IamPermissions.RolesManage)
            .WithName("AddPermissionsToBusinessRole")
            .Produces<BusinessRoleDto>(200);

        g.MapDelete("/{name}/permissions/{permission}", async (string name, string permission, IBusinessRoleStore store,
                Identity.Application.Scope.IScopeCacheInvalidator scopeCache, CancellationToken ct) =>
            {
                try
                {
                    await store.RemovePermissionAsync(name, permission, ct);
                    scopeCache.Invalidate();
                    var dto = await store.GetAsync(name, ct);
                    return dto is null
                        ? Results.NotFound(new ProblemResponse("not_found", $"business role '{name}' not found", Guid.NewGuid().ToString("N")))
                        : Results.Ok(dto);
                }
                catch (InvalidOperationException ex)
                {
                    return Results.BadRequest(new ProblemResponse("validation_error", ex.Message, Guid.NewGuid().ToString("N")));
                }
            }).RequireAuthorization(IamPermissions.RolesManage)
            .WithName("RemovePermissionFromBusinessRole")
            .Produces<BusinessRoleDto>(200);

        return g;
    }
}
