#pragma warning disable ASPDEPR002
using Identity.Application;
using Identity.Application.Scope;
using Identity.Contracts;
using Identity.Gateway.Errors;

namespace Identity.Gateway;

public static class BusinessRolesEndpoints
{
    public static RouteGroupBuilder MapBusinessRoles(this IEndpointRouteBuilder app)
    {
        var g = app.MapGroup("/api/identity/business-roles").WithTags("Business Roles");

        g.MapGet("", async (IBusinessRoleStore store, CancellationToken ct) =>
                (await store.ListAsync(ct)).ToHttpResult(roles => Results.Ok(roles)))
            .RequireAuthorization(IamPermissions.RolesRead)
            .WithName("ListBusinessRoles")
            .Produces<IReadOnlyCollection<BusinessRoleDto>>(200).ProducesProblem(503)
            .WithOpenApi(o => { o.Summary = "List business (composite) roles"; return o; });

        g.MapGet("/{name}", async (string name, IBusinessRoleStore store, CancellationToken ct) =>
                (await store.GetAsync(name, ct)).ToHttpResult(role => Results.Ok(role)))
            .RequireAuthorization(IamPermissions.RolesRead)
            .WithName("GetBusinessRole")
            .Produces<BusinessRoleDto>(200).ProducesProblem(404);

        g.MapGet("/{name}/effective-permissions", async (string name, IBusinessRoleStore store, CancellationToken ct) =>
                (await store.GetEffectivePermissionsAsync(name, ct))
                .ToHttpResult(perms => Results.Ok(new EffectivePermissionsResponse(name, perms))))
            .RequireAuthorization(IamPermissions.RolesRead)
            .WithName("GetEffectivePermissions")
            .Produces<EffectivePermissionsResponse>(200).ProducesProblem(404);

        g.MapPost("", async (CreateBusinessRoleRequest req, ProvisioningOrchestrator orch,
                IScopeCacheInvalidator scopeCache, CancellationToken ct) =>
            {
                var created = await orch.CreateBusinessRoleAsync(req.Name, req.Description, req.Permissions ?? [], ct);
                if (created.IsSuccess) scopeCache.Invalidate();
                return created.ToHttpResult(role =>
                    Results.Created($"/api/identity/business-roles/{Uri.EscapeDataString(role.Name)}", role));
            })
            .WithValidation<CreateBusinessRoleRequest>()
            .RequireAuthorization(IamPermissions.RolesManage)
            .WithName("CreateBusinessRole")
            .Produces<BusinessRoleDto>(201).ProducesProblem(400).ProducesProblem(409);

        g.MapPut("/{name}", async (string name, UpdateBusinessRoleRequest req, IBusinessRoleStore store,
                IScopeCacheInvalidator scopeCache, CancellationToken ct) =>
            {
                var updated = await store.UpdateAsync(name, req.Description, ct);
                if (!updated.IsSuccess) return updated.Error!.ToProblem();

                if (req.Permissions is not null)
                {
                    var permissions = await store.SetPermissionsAsync(name, req.Permissions, ct);
                    scopeCache.Invalidate();
                    if (!permissions.IsSuccess) return permissions.Error!.ToProblem();
                    updated = await store.GetAsync(name, ct);
                }

                scopeCache.Invalidate();
                return updated.ToHttpResult(role => Results.Ok(role));
            })
            .WithValidation<UpdateBusinessRoleRequest>()
            .RequireAuthorization(IamPermissions.RolesManage)
            .WithName("UpdateBusinessRole")
            .Produces<BusinessRoleDto>(200).ProducesProblem(400).ProducesProblem(404);

        g.MapDelete("/{name}", async (string name, ProvisioningOrchestrator orch,
                IScopeCacheInvalidator scopeCache, CancellationToken ct) =>
            {
                var deleted = await orch.DeleteBusinessRoleSafeAsync(name, ct);
                if (deleted.IsSuccess) scopeCache.Invalidate();
                return deleted.ToHttpResult(() => Results.NoContent());
            })
            .RequireAuthorization(IamPermissions.RolesManage)
            .WithName("DeleteBusinessRole")
            .Produces(204).ProducesProblem(404).ProducesProblem(409);

        g.MapPost("/{name}/permissions", async (string name, AssignPermissionsRequest req, IBusinessRoleStore store,
                IScopeCacheInvalidator scopeCache, CancellationToken ct) =>
            {
                // Existence is checked against Keycloak itself (the source of truth); the in-memory
                // registry is empty after a restart until services re-register.
                var added = await store.AddPermissionsAsync(name, req.Permissions, ct);
                if (!added.IsSuccess) return added.Error!.ToProblem();
                scopeCache.Invalidate();
                return (await store.GetAsync(name, ct)).ToHttpResult(role => Results.Ok(role));
            })
            .WithValidation<AssignPermissionsRequest>()
            .RequireAuthorization(IamPermissions.RolesManage)
            .WithName("AddPermissionsToBusinessRole")
            .Produces<BusinessRoleDto>(200).ProducesProblem(400).ProducesProblem(404);

        g.MapDelete("/{name}/permissions/{permission}", async (string name, string permission, IBusinessRoleStore store,
                IScopeCacheInvalidator scopeCache, CancellationToken ct) =>
            {
                var removed = await store.RemovePermissionAsync(name, permission, ct);
                if (!removed.IsSuccess) return removed.Error!.ToProblem();
                scopeCache.Invalidate();
                return (await store.GetAsync(name, ct)).ToHttpResult(role => Results.Ok(role));
            })
            .RequireAuthorization(IamPermissions.RolesManage)
            .WithName("RemovePermissionFromBusinessRole")
            .Produces<BusinessRoleDto>(200).ProducesProblem(404);

        return g;
    }
}
