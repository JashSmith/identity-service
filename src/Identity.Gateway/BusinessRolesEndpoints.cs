#pragma warning disable ASPDEPR002
using Avash.Identity.Abstractions;
using Identity.Application;
using Identity.Contracts;
using Identity.Gateway.Errors;

namespace Identity.Gateway;

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
                    ? Error.NotFound("resource.not_found", $"business role '{name}' not found").ToProblem()
                    : Results.Ok(dto);
            }).RequireAuthorization(IamPermissions.RolesRead)
            .WithName("GetBusinessRole")
            .Produces<BusinessRoleDto>(200);

        g.MapGet("/{name}/effective-permissions",
                async (string name, IBusinessRoleStore store, CancellationToken ct) =>
                {
                    var dto = await store.GetAsync(name, ct);
                    if (dto is null) return Error.NotFound("resource.not_found", $"business role '{name}' not found").ToProblem();
                    var perms = await store.GetEffectivePermissionsAsync(name, ct);
                    return Results.Ok(new EffectivePermissionsResponse(name, perms));
                }).RequireAuthorization(IamPermissions.RolesRead)
            .WithName("GetEffectivePermissions")
            .Produces<EffectivePermissionsResponse>(200);

        g.MapPost("", async (CreateBusinessRoleRequest req, ProvisioningOrchestrator orch,
                Identity.Application.Scope.IScopeCacheInvalidator scopeCache, CancellationToken ct) =>
            {
                if (string.IsNullOrWhiteSpace(req.Name))
                    return Error.Validation("request.invalid", "name is required").ToProblem();
                try
                {
                    var dto = await orch.CreateBusinessRoleAsync(req.Name, req.Description, req.Permissions ?? Array.Empty<string>(), ct);
                    scopeCache.Invalidate();
                    return Results.Created($"/api/identity/business-roles/{Uri.EscapeDataString(dto.Name)}", dto);
                }
                catch (InvalidOperationException ex) when (ex.Message.Contains("already exists", StringComparison.OrdinalIgnoreCase))
                {
                    return Error.Conflict("resource.conflict", ex.Message).ToProblem();
                }
                catch (InvalidOperationException ex)
                {
                    return Error.Validation("request.invalid", ex.Message).ToProblem();
                }
            }).RequireAuthorization(IamPermissions.RolesManage)
            .WithName("CreateBusinessRole")
            .Produces<BusinessRoleDto>(201).ProducesProblem(400).ProducesProblem(409);

        g.MapPut("/{name}", async (string name, UpdateBusinessRoleRequest req, IBusinessRoleStore store,
                Identity.Application.Scope.IScopeCacheInvalidator scopeCache, CancellationToken ct) =>
            {
                var dto = await store.UpdateAsync(name, req.Description, ct);
                if (dto is null)
                    return Error.NotFound("resource.not_found", $"business role '{name}' not found").ToProblem();

                if (req.Permissions is not null)
                {
                    var currentPerms = await store.GetEffectivePermissionsAsync(name, ct);
                    var incoming = req.Permissions.ToHashSet(StringComparer.OrdinalIgnoreCase);
                    var toRemove = currentPerms.Where(p => !incoming.Contains(p)).ToList();
                    var toAdd = req.Permissions.Where(p => !currentPerms.Contains(p, StringComparer.OrdinalIgnoreCase)).ToList();

                    foreach (var p in toRemove)
                    {
                        try { await store.RemovePermissionAsync(name, p, ct); } catch { /* ignore if not mapped */ }
                    }
                    if (toAdd.Count > 0)
                    {
                        try { await store.AddPermissionsAsync(name, toAdd, ct); } catch { /* best effort */ }
                    }
                    dto = await store.GetAsync(name, ct) ?? dto;
                }

                scopeCache.Invalidate();
                return Results.Ok(dto);
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
                        : Error.NotFound("resource.not_found", $"business role '{name}' not found").ToProblem();
                }
                catch (InvalidOperationException ex)
                {
                    return Error.Validation("request.invalid", ex.Message).ToProblem();
                }
            }).RequireAuthorization(IamPermissions.RolesManage)
            .WithName("DeleteBusinessRole")
            .Produces(204).ProducesProblem(400);

        g.MapPost("/{name}/permissions", async (string name, AssignPermissionsRequest req, IBusinessRoleStore store,
                Identity.Application.Scope.IScopeCacheInvalidator scopeCache, CancellationToken ct) =>
            {
                if (req.Permissions is null || req.Permissions.Count == 0)
                    return Error.Validation("request.invalid", "permissions are required").ToProblem();
                // Existence is validated against Keycloak itself (the source of truth) inside
                // AddPermissionsAsync — the in-memory registry is empty after a gateway restart
                // until services re-register, so it must not reject valid permissions.
                try
                {
                    await store.AddPermissionsAsync(name, req.Permissions, ct);
                    scopeCache.Invalidate();
                    var dto = await store.GetAsync(name, ct);
                    return dto is null
                        ? Error.NotFound("resource.not_found", $"business role '{name}' not found").ToProblem()
                        : Results.Ok(dto);
                }
                catch (InvalidOperationException ex)
                {
                    return Error.Validation("request.invalid", ex.Message).ToProblem();
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
                        ? Error.NotFound("resource.not_found", $"business role '{name}' not found").ToProblem()
                        : Results.Ok(dto);
                }
                catch (InvalidOperationException ex)
                {
                    return Error.Validation("request.invalid", ex.Message).ToProblem();
                }
            }).RequireAuthorization(IamPermissions.RolesManage)
            .WithName("RemovePermissionFromBusinessRole")
            .Produces<BusinessRoleDto>(200);

        return g;
    }
}
