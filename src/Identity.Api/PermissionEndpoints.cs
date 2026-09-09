#pragma warning disable ASPDEPR002
using Identity.Application;
using Identity.Contracts;

namespace Identity.Api;

public static class PermissionEndpoints
{
    public static RouteGroupBuilder MapPermissions(this IEndpointRouteBuilder app)
    {
        var g = app.MapGroup("/api/identity/permissions").WithTags("Permissions");
        g.MapPost("/register", async (PermissionManifestRequest req, PermissionRegistrationService svc, HttpContext ctx, CancellationToken ct) =>
        {
            var serviceId = ctx.User.FindFirst("client_id")?.Value ?? ctx.User.FindFirst("azp")?.Value ?? req.ServiceId;
            var res = await svc.RegisterAsync(req, serviceId, ct);
            return Results.Ok(res);
        }).RequireAuthorization("Identity.Permissions.Register")
          .WithName("RegisterPermissions").Produces<ManifestRegistrationResponse>(200)
          .WithOpenApi(o => { o.Summary = "Register/refresh a service permission manifest"; o.Description = "Failure here must not prevent app start. Missing permissions are deprecated, never auto-deleted."; return o; });
        return g;
    }
}
