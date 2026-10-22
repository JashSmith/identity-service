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
        g.MapPost("", async (
                CreatePermissionRequest req,
                IPermissionRegistry registry,
                CancellationToken ct
            ) =>
            {
                if (string.IsNullOrWhiteSpace(req.Name))
                    return Results.BadRequest(new ProblemResponse("validation_error", "permission name is required", Guid.NewGuid().ToString("N")));

                var permName = req.Name.Trim();
                var desc = string.IsNullOrWhiteSpace(req.Description) ? $"Permission {permName}" : req.Description.Trim();
                var serviceId = string.IsNullOrWhiteSpace(req.ServiceId)
                    ? (permName.Contains('.') ? permName.Split('.')[0].ToLowerInvariant() + "-service" : "identity-facade")
                    : req.ServiceId.Trim();

                var manifest = new PermissionManifestRequest(
                    serviceId,
                    "1.0.0",
                    "1",
                    new[] { new PermissionDefinitionDto(permName, desc) },
                    "manual:" + Guid.NewGuid().ToString("N"));

                try
                {
                    // Empty authenticatedServiceId bypasses strict per-service prefix validation for admin registration
                    await registry.RegisterAsync(manifest, "", ct);
                    var dto = new PermissionDto(permName, desc, serviceId, "1.0.0", false);
                    return Results.Created($"/api/identity/permissions?serviceId={Uri.EscapeDataString(serviceId)}", dto);
                }
                catch (InvalidOperationException ex)
                {
                    return Results.BadRequest(new ProblemResponse("validation_error", ex.Message, Guid.NewGuid().ToString("N")));
                }
            }).RequireAuthorization("Identity.Permissions.Register")
            .WithName("CreatePermission")
            .Produces<PermissionDto>(201)
            .Produces<ProblemResponse>(400)
            .WithOpenApi(o =>
            {
                o.Summary = "Manually register a single permission";
                o.Description = "Creates matching Keycloak client role on the owning client, maps it to Admin group, and registers in permissions catalog.";
                return o;
            });

        return g;
    }
}

public sealed record CreatePermissionRequest(string Name, string? Description, string? ServiceId);