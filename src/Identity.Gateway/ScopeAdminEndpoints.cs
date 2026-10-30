using Identity.Application.Scope;
using Identity.Contracts;
using Identity.Gateway.Errors;

namespace Identity.Gateway;

/// <summary>
/// Scope-registry admin endpoints. The Keycloak <c>iam-scope-registry</c> group is the source of truth;
/// creating a scope also declares its user attribute and token claim (or fails and leaves nothing behind).
/// </summary>
public static class ScopeAdminEndpoints
{
    public static RouteGroupBuilder MapScopeAdmin(this IEndpointRouteBuilder app)
    {
        var g = app.MapGroup("/api/identity/scopes").WithTags("Scopes");

        g.MapGet("", async (IScopeRegistryAdmin registry, CancellationToken ct) =>
                (await registry.ListScopesAsync(ct)).ToHttpResult(scopes => Results.Ok(scopes)))
            .RequireAuthorization(IamPermissions.ScopesRead)
            .WithName("ListScopes")
            .Produces<IReadOnlyCollection<ScopeDefinitionDto>>(200);

        g.MapGet("/resources/list", async (IScopeRegistryAdmin registry, CancellationToken ct) =>
                (await registry.ListResourcesAsync(ct)).ToHttpResult(resources => Results.Ok(resources)))
            .RequireAuthorization(IamPermissions.ScopesRead)
            .WithName("ListResources")
            .Produces<IReadOnlyCollection<ResourceScopeMappingDto>>(200);

        g.MapGet("/{key}", async (string key, IScopeRegistryAdmin registry, CancellationToken ct) =>
                (await registry.GetScopeAsync(key, ct)).ToHttpResult(scope => Results.Ok(scope)))
            .RequireAuthorization(IamPermissions.ScopesRead)
            .WithName("GetScope")
            .Produces<ScopeDefinitionDto>(200).ProducesProblem(404);

        g.MapGet("/{key}/resources", async (string key, IScopeRegistryAdmin registry, CancellationToken ct) =>
                (await registry.GetResourcesForScopeAsync(key, ct)).ToHttpResult(resources => Results.Ok(new { scope = key, resources })))
            .RequireAuthorization(IamPermissions.ScopesRead)
            .WithName("GetScopeResources")
            .Produces<object>(200).ProducesProblem(404);

        g.MapPost("", async (CreateScopeRequest req, IScopeRegistryAdmin registry, CancellationToken ct) =>
                (await registry.CreateScopeAsync(req.Key.Trim(), req.DisplayName, req.Description, req.TargetResources, ct))
                .ToHttpResult(created => Results.Created($"/api/identity/scopes/{Uri.EscapeDataString(created.Key)}", created)))
            .WithValidation<CreateScopeRequest>()
            .RequireAuthorization(IamPermissions.ScopesManage)
            .WithName("CreateScope")
            .Produces<ScopeDefinitionDto>(201).ProducesProblem(400).ProducesProblem(409);

        g.MapPut("/{key}", async (string key, UpdateScopeRequest req, IScopeRegistryAdmin registry, CancellationToken ct) =>
                (await registry.UpdateScopeAsync(key, req.DisplayName, req.Description, req.IsActive, req.TargetResources, ct))
                .ToHttpResult(updated => Results.Ok(updated)))
            .WithValidation<UpdateScopeRequest>()
            .RequireAuthorization(IamPermissions.ScopesManage)
            .WithName("UpdateScope")
            .Produces<ScopeDefinitionDto>(200).ProducesProblem(400).ProducesProblem(404);

        g.MapPut("/{key}/resources", async (string key, SetScopeResourcesRequest req, IScopeRegistryAdmin registry, CancellationToken ct) =>
                (await registry.SetScopeResourcesAsync(key, req.Resources ?? [], ct))
                .ToHttpResult(() => Results.Ok(new { scope = key, resources = req.Resources ?? [] })))
            .WithValidation<SetScopeResourcesRequest>()
            .RequireAuthorization(IamPermissions.ScopesManage)
            .WithName("SetScopeResources")
            .Produces<object>(200).ProducesProblem(400).ProducesProblem(404);

        g.MapDelete("/{key}", async (string key, IScopeRegistryAdmin registry, CancellationToken ct) =>
                (await registry.DeleteScopeAsync(key, ct)).ToHttpResult(() => Results.NoContent()))
            .RequireAuthorization(IamPermissions.ScopesManage)
            .WithName("DeleteScope")
            .Produces(204).ProducesProblem(404);

        return g;
    }
}
