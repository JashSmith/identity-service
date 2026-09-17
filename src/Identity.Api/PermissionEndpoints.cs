#pragma warning disable ASPDEPR002
using Identity.Application;
using Identity.Contracts;

namespace Identity.Api;

public static class PermissionEndpoints
{
    public static RouteGroupBuilder MapPermissions(this IEndpointRouteBuilder app)
    {
        var g = app.MapGroup("/api/identity/permissions").WithTags("Permissions");
        g.MapPost("/register", async (
                PermissionManifestRequest req, PermissionRegistrationService svc, HttpContext ctx, CancellationToken ct
            ) =>
            {
                var serviceId = ctx.User.FindFirst("client_id")?.Value ??
                                ctx.User.FindFirst("azp")?.Value ?? req.ServiceId;
                try
                {
                    var res = await svc.RegisterAsync(req, serviceId, ct);
                    return Results.Ok(res);
                }
                catch (InvalidOperationException ex)
                {
                    return Results.BadRequest(new ProblemResponse("validation_error", ex.Message, Guid.NewGuid().ToString("N")));
                }
            }).RequireAuthorization("Identity.Permissions.Register")
            .WithName("RegisterPermissions").Produces<ManifestRegistrationResponse>(200).Produces<ProblemResponse>(400)
            .WithOpenApi(o =>
            {
                o.Summary = "Register/refresh a service permission manifest";
                o.Description =
                    "Permissions become client roles on the owning service client (per-service client-role mapper -> permissions claim). " +
                    "Missing permissions are deprecated, never auto-deleted. Namespace is enforced (e.g. order-service may only register Orders.*).";
                return o;
            });
        g.MapPost("/reconcile-admin", async (IKeycloakClientRoleProvisioner provisioner, CancellationToken ct) =>
            {
                var added = await provisioner.ReconcileAdminAsync(ct);
                return Results.Ok(new { added });
            }).RequireAuthorization("Identity.Permissions.Register")
            .WithName("ReconcileAdminPermissions").Produces<object>(200)
            .WithOpenApi(o =>
            {
                o.Summary = "Reconcile Admin group — backfill any registered client roles missing from key-admins";
                o.Description = "Idempotent. Adds all registered client roles not yet mapped to the Admin group (key-admins). Repairs drift / manual edits.";
                return o;
            });
        return g;
    }
}