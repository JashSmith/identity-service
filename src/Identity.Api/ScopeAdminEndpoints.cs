#pragma warning disable CS0618
using Identity.Application.Scope;
using Identity.Contracts;
using Identity.Persistence.KeyManagement;
using Microsoft.EntityFrameworkCore;

namespace Identity.Api;

public static class ScopeAdminEndpoints
{
    public static RouteGroupBuilder MapScopeAdmin(this IEndpointRouteBuilder app)
    {
        var g = app.MapGroup("/api/identity/scopes").WithTags("Scopes");

        g.MapGet("", async (KeyMetadataDbContext db, CancellationToken ct) =>
        {
            var list = await db.ScopeDefinitions.OrderBy(s => s.Key).ToListAsync(ct);
            return Results.Ok(list.Select(s => new { s.Key, s.DisplayName, s.Description, s.IsActive, s.ValueType }));
        }).RequireAuthorization(IamPermissions.ScopesRead).WithName("ListScopes");

        g.MapGet("/{key}", async (string key, KeyMetadataDbContext db, CancellationToken ct) =>
        {
            var s = await db.ScopeDefinitions.FirstOrDefaultAsync(x => x.Key == key, ct);
            return s is null ? Results.NotFound() : Results.Ok(new { s.Key, s.DisplayName, s.Description, s.IsActive, s.ValueType });
        }).RequireAuthorization(IamPermissions.ScopesRead).WithName("GetScope");

        g.MapGet("/{key}/resources", async (string key, KeyMetadataDbContext db, CancellationToken ct) =>
        {
            var def = await db.ScopeDefinitions.FirstOrDefaultAsync(x => x.Key == key, ct);
            if (def is null) return Results.NotFound();
            var resources = await (from m in db.ScopeResourceMappings
                                   join r in db.ApplicationResources on m.ApplicationResourceId equals r.Id
                                   where m.ScopeDefinitionId == def.Id
                                   select r.Key).ToListAsync(ct);
            return Results.Ok(new { scope = key, resources });
        }).RequireAuthorization(IamPermissions.ScopesRead).WithName("GetScopeResources");

        g.MapPost("", async (CreateScopeRequest req, KeyMetadataDbContext db, IScopeCacheInvalidator cache, CancellationToken ct) =>
        {
            if (string.IsNullOrWhiteSpace(req.Key)) return Results.ValidationProblem(new Dictionary<string, string[]> { ["key"] = ["Key is required."] });
            if (await db.ScopeDefinitions.AnyAsync(x => x.Key == req.Key, ct))
                return Results.Conflict(new ProblemResponse("conflict", $"Scope '{req.Key}' already exists.", Guid.NewGuid().ToString("N")));
            var e = new ScopeDefinitionEntity { Id = Guid.NewGuid(), Key = req.Key.Trim(), DisplayName = req.DisplayName ?? req.Key, Description = req.Description, IsActive = true, ValueType = "String", CreatedAt = DateTimeOffset.UtcNow, UpdatedAt = DateTimeOffset.UtcNow };
            db.ScopeDefinitions.Add(e);
            await db.SaveChangesAsync(ct);
            cache.Invalidate();
            return Results.Created($"/api/identity/scopes/{e.Key}", e);
        }).RequireAuthorization(IamPermissions.ScopesManage).WithName("CreateScope");

        g.MapPut("/{key}", async (string key, UpdateScopeRequest req, KeyMetadataDbContext db, IScopeCacheInvalidator cache, CancellationToken ct) =>
        {
            var e = await db.ScopeDefinitions.FirstOrDefaultAsync(x => x.Key == key, ct);
            if (e is null) return Results.NotFound();
            if (req.DisplayName is not null) e.DisplayName = req.DisplayName;
            if (req.Description is not null) e.Description = req.Description;
            if (req.IsActive is not null) e.IsActive = req.IsActive.Value;
            e.UpdatedAt = DateTimeOffset.UtcNow;
            await db.SaveChangesAsync(ct);
            cache.Invalidate();
            return Results.Ok(e);
        }).RequireAuthorization(IamPermissions.ScopesManage).WithName("UpdateScope");

        g.MapGet("/resources/list", async (KeyMetadataDbContext db, CancellationToken ct) =>
        {
            var list = await db.ApplicationResources.OrderBy(r => r.Key).ToListAsync(ct);
            return Results.Ok(list.Select(r => new { r.Key, r.DisplayName }));
        }).RequireAuthorization(IamPermissions.ScopesRead).WithName("ListResources");

        return g;
    }
}

public sealed record CreateScopeRequest(string Key, string? DisplayName, string? Description);
public sealed record UpdateScopeRequest(string? DisplayName, string? Description, bool? IsActive);
