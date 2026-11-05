#pragma warning disable ASPDEPR002
using Identity.Application;
using Identity.Application.Permissions;
using Identity.Contracts;
using Identity.Gateway.Errors;

namespace Identity.Gateway;

/// <summary>Applications and their permission catalog.</summary>
public static class PermissionEndpoints
{
    public static void MapPermissions(this IEndpointRouteBuilder app)
    {
        var apps = app.MapGroup("/api/identity/applications").WithTags("Applications");

        apps.MapGet("", async (IApplicationCatalog catalog, CancellationToken ct) =>
                (await catalog.ListAsync(ct)).ToHttpResult(list => Results.Ok(list)))
            .RequireAuthorization(IamPermissions.ApplicationsRead).WithName("ListApplications")
            .Produces<IReadOnlyCollection<ApplicationDto>>(200);

        apps.MapGet("/{clientId}", async (string clientId, IApplicationCatalog catalog, CancellationToken ct) =>
                (await catalog.GetAsync(clientId, ct)).ToHttpResult(a => Results.Ok(a)))
            .RequireAuthorization(IamPermissions.ApplicationsRead).WithName("GetApplication")
            .Produces<ApplicationDto>(200).ProducesProblem(404);

        apps.MapPost("", async (CreateApplicationRequest req, IApplicationCatalog catalog, CancellationToken ct) =>
                (await catalog.CreateAsync(req, ct)).ToHttpResult(created =>
                    Results.Created($"/api/identity/applications/{Uri.EscapeDataString(created.Application.ClientId)}", created)))
            .WithValidation<CreateApplicationRequest>()
            .RequireAuthorization(IamPermissions.ApplicationsManage).WithName("CreateApplication")
            .Produces<ApplicationSecretResponse>(201).ProducesProblem(400).ProducesProblem(409);

        apps.MapPut("/{clientId}", async (string clientId, UpdateApplicationRequest req, IApplicationCatalog catalog, CancellationToken ct) =>
                (await catalog.UpdateAsync(clientId, req, ct)).ToHttpResult(a => Results.Ok(a)))
            .WithValidation<UpdateApplicationRequest>()
            .RequireAuthorization(IamPermissions.ApplicationsManage).WithName("UpdateApplication")
            .Produces<ApplicationDto>(200).ProducesProblem(404);

        apps.MapDelete("/{clientId}", async (string clientId, IApplicationCatalog catalog, CancellationToken ct) =>
                (await catalog.DeleteAsync(clientId, ct)).ToHttpResult(() => Results.NoContent()))
            .RequireAuthorization(IamPermissions.ApplicationsManage).WithName("DeleteApplication")
            .Produces(204).ProducesProblem(400).ProducesProblem(404);

        apps.MapPost("/{clientId}/secret", async (string clientId, IApplicationCatalog catalog, CancellationToken ct) =>
                (await catalog.RotateSecretAsync(clientId, ct)).ToHttpResult(s => Results.Ok(s)))
            .RequireAuthorization(IamPermissions.ApplicationsManage).WithName("RotateApplicationSecret")
            .Produces<ApplicationSecretResponse>(200).ProducesProblem(404);

        apps.MapGet("/{clientId}/permissions", async (string clientId, bool? includeDeprecated, IPermissionCatalog catalog, CancellationToken ct) =>
                (await catalog.ListAsync(clientId, includeDeprecated ?? false, ct)).ToHttpResult(list => Results.Ok(list)))
            .RequireAuthorization(IamPermissions.PermissionsRead).WithName("ListApplicationPermissions")
            .Produces<IReadOnlyCollection<CatalogPermissionDto>>(200).ProducesProblem(404);

        apps.MapPost("/{clientId}/permissions", async (string clientId, CreateCatalogPermissionRequest req, IPermissionCatalog catalog, CancellationToken ct) =>
                (await catalog.CreateAsync(clientId, req, ct)).ToHttpResult(p =>
                    Results.Created($"/api/identity/applications/{Uri.EscapeDataString(clientId)}/permissions/{Uri.EscapeDataString(p.Module + ":" + p.Resource + ":" + p.Action)}", p)))
            .WithValidation<CreateCatalogPermissionRequest>()
            .RequireAuthorization(IamPermissions.PermissionsManage).WithName("CreatePermission")
            .Produces<CatalogPermissionDto>(201).ProducesProblem(400).ProducesProblem(409);

        apps.MapPut("/{clientId}/permissions/{name}", async (string clientId, string name, UpdateCatalogPermissionRequest req, IPermissionCatalog catalog, CancellationToken ct) =>
                (await catalog.UpdateAsync(clientId, name, req, ct)).ToHttpResult(p => Results.Ok(p)))
            .WithValidation<UpdateCatalogPermissionRequest>()
            .RequireAuthorization(IamPermissions.PermissionsManage).WithName("UpdatePermission")
            .Produces<CatalogPermissionDto>(200).ProducesProblem(404);

        apps.MapDelete("/{clientId}/permissions/{name}", async (string clientId, string name, IPermissionCatalog catalog, CancellationToken ct) =>
                (await catalog.DeleteAsync(clientId, name, ct)).ToHttpResult(() => Results.NoContent()))
            .RequireAuthorization(IamPermissions.PermissionsManage).WithName("DeletePermission")
            .Produces(204).ProducesProblem(404);

        var perms = app.MapGroup("/api/identity/permissions").WithTags("Permissions");

        perms.MapGet("", async (string? application, bool? includeDeprecated, IPermissionCatalog catalog, CancellationToken ct) =>
                (await catalog.ListAsync(application, includeDeprecated ?? false, ct)).ToHttpResult(list => Results.Ok(list)))
            .RequireAuthorization(IamPermissions.PermissionsRead).WithName("ListPermissions")
            .Produces<IReadOnlyCollection<CatalogPermissionDto>>(200);

        perms.MapGet("/tree", async (bool? includeDeprecated, IPermissionCatalog catalog, CancellationToken ct) =>
                (await catalog.GetTreeAsync(includeDeprecated ?? false, ct)).ToHttpResult(tree => Results.Ok(tree)))
            .RequireAuthorization(IamPermissions.PermissionsRead).WithName("GetPermissionTree")
            .Produces<PermissionTreeDto>(200);

        // Called by each service with its own service-account token: the namespace is the caller's client id.
        perms.MapPost("/register", async (PermissionManifestRequest req, HttpContext http, IPermissionCatalog catalog, CancellationToken ct) =>
            {
                var caller = http.User.FindFirst("azp")?.Value ?? http.User.FindFirst("client_id")?.Value;
                if (string.IsNullOrEmpty(caller))
                    return Error.Forbidden("application.not_registered", "Only an application's service account can register its manifest.").ToProblem();
                return (await catalog.RegisterManifestAsync(caller, req, ct)).ToHttpResult(r => Results.Ok(r));
            })
            .WithValidation<PermissionManifestRequest>()
            .RequireAuthorization().WithName("RegisterPermissions")
            .Produces<ManifestRegistrationResponse>(200).ProducesProblem(400).ProducesProblem(403);

        perms.MapPost("/reconcile-admin", async (IKeycloakClientRoleProvisioner provisioner, CancellationToken ct) =>
                (await provisioner.ReconcileAdminAsync(ct)).ToHttpResult(added => Results.Ok(new { added })))
            .RequireAuthorization(IamPermissions.PermissionsManage).WithName("ReconcileAdminPermissions")
            .Produces<object>(200);
    }
}
