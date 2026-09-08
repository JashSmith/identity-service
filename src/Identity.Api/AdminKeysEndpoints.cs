using Company.Identity.Authorization.AspNetCore;
using Identity.Application;
using Identity.Contracts;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace Identity.Api;

public static class AdminKeysEndpoints
{
    public static RouteGroupBuilder MapAdminKeys(this IEndpointRouteBuilder app)
    {
        var g = app.MapGroup("/api/admin/identity/keys").RequireAuthorization();
        g.MapPost("/generate", async (GenerateKeyRequest req, KeyRotationService svc, HttpContext ctx, CancellationToken ct) =>
        {
            var actor = ctx.User.Identity?.Name ?? "admin";
            return Results.Ok(await svc.GenerateAsync(req, actor, ct));
        }).RequireAuthorization(KeyPermissions.Generate);
        g.MapPost("/import", async (ImportKeyRequest req, KeyRotationService svc, HttpContext ctx, CancellationToken ct) =>
        {
            var actor = ctx.User.Identity?.Name ?? "admin";
            return Results.Ok(await svc.ImportAsync(req, actor, ct));
        }).RequireAuthorization(KeyPermissions.Import);
        g.MapGet("/", async (int? page, int? pageSize, KeyRotationService svc, CancellationToken ct) =>
            Results.Ok(await svc.ListAsync(page ?? 1, pageSize ?? 20, ct))).RequireAuthorization(KeyPermissions.View);
        g.MapGet("/{kid}", async (string kid, KeyRotationService svc, CancellationToken ct) =>
        {
            var d = await svc.GetAsync(kid, ct);
            return d is null ? Results.NotFound() : Results.Ok(d);
        }).RequireAuthorization(KeyPermissions.View);
        g.MapGet("/{kid}/history", async (string kid, KeyRotationService svc, CancellationToken ct) =>
            Results.Ok(await svc.HistoryAsync(kid, ct))).RequireAuthorization(KeyPermissions.History);
        g.MapGet("/rotation/state", async (KeyRotationService svc, CancellationToken ct) =>
            Results.Ok(await svc.RotationStateAsync(ct))).RequireAuthorization(KeyPermissions.View);
        g.MapPost("/{kid}/stage", async (string kid, KeyRotationService svc, HttpContext ctx, CancellationToken ct) =>
            Results.Ok(await svc.StageAsync(kid, ctx.User.Identity?.Name ?? "admin", ct))).RequireAuthorization(KeyPermissions.Stage);
        g.MapPost("/{kid}/validate", async (string kid, KeyRotationService svc, HttpContext ctx, CancellationToken ct) =>
            Results.Ok(await svc.ValidateAsync(kid, ctx.User.Identity?.Name ?? "admin", ct))).RequireAuthorization(KeyPermissions.Validate);
        g.MapPost("/{kid}/activate", async (string kid, string? idempotencyKey, KeyRotationService svc, HttpContext ctx, CancellationToken ct) =>
            Results.Ok(await svc.ActivateAsync(kid, ctx.User.Identity?.Name ?? "admin", idempotencyKey, ct))).RequireAuthorization(KeyPermissions.Activate);
        g.MapPost("/{kid}/retire", async (string kid, KeyRotationService svc, HttpContext ctx, CancellationToken ct) =>
            Results.Ok(await svc.RetireAsync(kid, ctx.User.Identity?.Name ?? "admin", ct))).RequireAuthorization(KeyPermissions.Retire);
        g.MapPost("/{kid}/destroy", async (string kid, DestroyRequest req, KeyRotationService svc, HttpContext ctx, CancellationToken ct) =>
        {
            await svc.DestroyAsync(kid, req, ctx.User.Identity?.Name ?? "admin", ct);
            return Results.NoContent();
        }).RequireAuthorization(KeyPermissions.Destroy);
        g.MapPost("/rotate", async (RotateRequest req, KeyRotationService svc, HttpContext ctx, CancellationToken ct) =>
            Results.Ok(await svc.RotateAsync(req, ctx.User.Identity?.Name ?? "admin", ct))).RequireAuthorization(KeyPermissions.Rotate);
        g.MapPost("/rotate/emergency", async (EmergencyRotateRequest req, KeyRotationService svc, HttpContext ctx, CancellationToken ct) =>
            Results.Ok(await svc.EmergencyRotateAsync(req, ctx.User.Identity?.Name ?? "admin", ct))).RequireAuthorization(KeyPermissions.EmergencyRotate);
        g.MapPost("/{kid}/rollback", async (string kid, RollbackRequest req, KeyRotationService svc, HttpContext ctx, CancellationToken ct) =>
            Results.Ok(await svc.RollbackAsync(kid, req, ctx.User.Identity?.Name ?? "admin", ct))).RequireAuthorization(KeyPermissions.Rollback);
        g.MapGet("/{kid}/safety", async (string kid, KeyRotationService svc, CancellationToken ct) =>
            Results.Ok(await svc.AssessDestroySafetyAsync(kid, ct))).RequireAuthorization(KeyPermissions.View);
        return g;
    }
}
