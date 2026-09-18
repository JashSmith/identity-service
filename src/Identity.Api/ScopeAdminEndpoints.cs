using Identity.Application.Scope;
using Identity.Contracts;

namespace Identity.Api;

/// <summary>
/// Scope-registry admin endpoints. The Keycloak <c>iam-scope-registry</c> group is the
/// source of truth (no Oracle scope tables); all reads/writes go through IScopeRegistryAdmin.
/// </summary>
public static class ScopeAdminEndpoints
{
    public static RouteGroupBuilder MapScopeAdmin(this IEndpointRouteBuilder app)
    {
        var g = app.MapGroup("/api/identity/scopes").WithTags("Scopes");

        g.MapGet("", async (IScopeRegistryAdmin registry, CancellationToken ct) =>
                Results.Ok(await registry.ListScopesAsync(ct)))
            .RequireAuthorization(IamPermissions.ScopesRead)
            .WithName("ListScopes")
            .Produces<IReadOnlyCollection<ScopeDefinitionDto>>(200);

        g.MapGet("/resources/list", async (IScopeRegistryAdmin registry, CancellationToken ct) =>
                Results.Ok(await registry.ListResourcesAsync(ct)))
            .RequireAuthorization(IamPermissions.ScopesRead)
            .WithName("ListResources")
            .Produces<IReadOnlyCollection<ResourceScopeMappingDto>>(200);

        g.MapGet("/{key}", async (string key, IScopeRegistryAdmin registry, CancellationToken ct) =>
            {
                var s = await registry.GetScopeAsync(key, ct);
                return s is null
                    ? Results.NotFound(new ProblemResponse("not_found", $"scope '{key}' not found", Guid.NewGuid().ToString("N")))
                    : Results.Ok(s);
            })
            .RequireAuthorization(IamPermissions.ScopesRead)
            .WithName("GetScope")
            .Produces<ScopeDefinitionDto>(200);

        g.MapGet("/{key}/resources", async (string key, IScopeRegistryAdmin registry, CancellationToken ct) =>
            {
                if (await registry.GetScopeAsync(key, ct) is null)
                    return Results.NotFound(new ProblemResponse("not_found", $"scope '{key}' not found", Guid.NewGuid().ToString("N")));
                var resources = await registry.GetResourcesForScopeAsync(key, ct);
                return Results.Ok(new { scope = key, resources });
            })
            .RequireAuthorization(IamPermissions.ScopesRead)
            .WithName("GetScopeResources")
            .Produces<object>(200);

        g.MapPost("", async (CreateScopeRequest req, IScopeRegistryAdmin registry,
                Identity.Infrastructure.Keycloak.KeycloakScopeClaimMapper claimMapper,
                Identity.Infrastructure.Keycloak.KeycloakUserProfileHardening profileHardening, CancellationToken ct) =>
            {
                if (string.IsNullOrWhiteSpace(req.Key))
                    return Results.ValidationProblem(new Dictionary<string, string[]> { ["key"] = ["Key is required."] });
                try
                {
                    var created = await registry.CreateScopeAsync(req.Key.Trim(), req.DisplayName, req.Description, ct);
                    if (created is null)
                        return Results.Conflict(new ProblemResponse("conflict", $"Scope '{req.Key}' already exists.", Guid.NewGuid().ToString("N")));
                    // Provision the authz.scope.<key> claim mapper now so new tokens carry the
                    // claim without a restart. Best-effort: startup EnsureAsync also reconciles.
                    using var mapperCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    mapperCts.CancelAfter(TimeSpan.FromSeconds(10));
                    try { await claimMapper.EnsureAsync(mapperCts.Token); } catch { /* best-effort */ }
                    // Declare authz.scope.<key> in the User Profile — Keycloak silently discards
                    // undeclared attributes, so without this the new scope could never be written.
                    try { await profileHardening.EnsureAsync(mapperCts.Token); } catch { /* best-effort */ }
                    return Results.Created($"/api/identity/scopes/{Uri.EscapeDataString(created.Key)}", created);
                }
                catch (InvalidOperationException ex)
                {
                    return Results.BadRequest(new ProblemResponse("validation_error", ex.Message, Guid.NewGuid().ToString("N")));
                }
            })
            .RequireAuthorization(IamPermissions.ScopesManage)
            .WithName("CreateScope")
            .Produces<ScopeDefinitionDto>(201);

        g.MapPut("/{key}", async (string key, UpdateScopeRequest req, IScopeRegistryAdmin registry, CancellationToken ct) =>
            {
                try
                {
                    var updated = await registry.UpdateScopeAsync(key, req.DisplayName, req.Description, req.IsActive, ct);
                    return updated is null
                        ? Results.NotFound(new ProblemResponse("not_found", $"scope '{key}' not found", Guid.NewGuid().ToString("N")))
                        : Results.Ok(updated);
                }
                catch (InvalidOperationException ex)
                {
                    return Results.BadRequest(new ProblemResponse("validation_error", ex.Message, Guid.NewGuid().ToString("N")));
                }
            })
            .RequireAuthorization(IamPermissions.ScopesManage)
            .WithName("UpdateScope")
            .Produces<ScopeDefinitionDto>(200);

        return g;
    }
}

public sealed record CreateScopeRequest(string Key, string? DisplayName, string? Description);
public sealed record UpdateScopeRequest(string? DisplayName, string? Description, bool? IsActive);
