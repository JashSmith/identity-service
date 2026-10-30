using Identity.Application;
using Identity.Contracts;
using Identity.Gateway.Errors;

namespace Identity.Gateway;

/// <summary>
/// Account lifecycle: brute-force lockout, credentials (e.g. resetting a lost OTP device), required actions and
/// action emails. Every per-user route is limited to users the administrator may manage.
/// </summary>
public static class UserLifecycleEndpoints
{
    public static IEndpointRouteBuilder MapUserLifecycle(this IEndpointRouteBuilder app)
    {
        app.MapGet("/api/identity/required-actions", async (IUserLifecycleService svc, CancellationToken ct) =>
                (await svc.GetRequiredActionCatalogAsync(ct)).ToHttpResult(actions => Results.Ok(actions)))
            .WithTags("Users")
            .RequireAuthorization(IamPermissions.UsersRead)
            .WithName("ListRequiredActions")
            .Produces<IReadOnlyCollection<RequiredActionDto>>(200);

        var g = app.MapGroup("/api/identity/users/{id}").WithTags("Users");

        g.MapGet("/lockout", async (string id, IUserLifecycleService svc, CancellationToken ct) =>
                (await svc.GetLockoutAsync(id, ct)).ToHttpResult(lockout => Results.Ok(lockout)))
            .RequireAuthorization(IamPermissions.UsersRead)
            .ForManageableUser()
            .WithName("GetUserLockout")
            .Produces<UserLockoutDto>(200).ProducesProblem(404);

        g.MapDelete("/lockout", async (string id, IUserLifecycleService svc, CancellationToken ct) =>
                (await svc.UnlockAsync(id, ct)).ToHttpResult(() => Results.NoContent()))
            .RequireAuthorization(IamPermissions.UsersManage)
            .ForManageableUser()
            .WithName("UnlockUser")
            .Produces(204).ProducesProblem(404);

        g.MapGet("/credentials", async (string id, IUserLifecycleService svc, CancellationToken ct) =>
                (await svc.GetCredentialsAsync(id, ct)).ToHttpResult(credentials => Results.Ok(credentials)))
            .RequireAuthorization(IamPermissions.UsersRead)
            .ForManageableUser()
            .WithName("GetUserCredentials")
            .Produces<IReadOnlyCollection<UserCredentialDto>>(200).ProducesProblem(404);

        g.MapDelete("/credentials/{credentialId}", async (string id, string credentialId, IUserLifecycleService svc, CancellationToken ct) =>
                (await svc.DeleteCredentialAsync(id, credentialId, ct)).ToHttpResult(() => Results.NoContent()))
            .RequireAuthorization(IamPermissions.UsersManage)
            .ForManageableUser()
            .WithName("DeleteUserCredential")
            .Produces(204).ProducesProblem(404);

        g.MapGet("/required-actions", async (string id, IUserLifecycleService svc, CancellationToken ct) =>
                (await svc.GetRequiredActionsAsync(id, ct)).ToHttpResult(actions => Results.Ok(actions)))
            .RequireAuthorization(IamPermissions.UsersRead)
            .ForManageableUser()
            .WithName("GetUserRequiredActions")
            .Produces<IReadOnlyCollection<string>>(200).ProducesProblem(404);

        g.MapPut("/required-actions", async (string id, SetRequiredActionsRequest req, IUserLifecycleService svc, CancellationToken ct) =>
                (await svc.SetRequiredActionsAsync(id, req.Actions, ct)).ToHttpResult(() => Results.Ok(req.Actions)))
            .WithValidation<SetRequiredActionsRequest>()
            .RequireAuthorization(IamPermissions.UsersManage)
            .ForManageableUser()
            .WithName("SetUserRequiredActions")
            .Produces<IReadOnlyCollection<string>>(200).ProducesProblem(400).ProducesProblem(404);

        g.MapPost("/execute-actions-email", async (string id, SendActionsEmailRequest req, IUserLifecycleService svc, CancellationToken ct) =>
                (await svc.SendActionsEmailAsync(id, req, ct)).ToHttpResult(() => Results.Accepted()))
            .WithValidation<SendActionsEmailRequest>()
            .RequireAuthorization(IamPermissions.UsersManage)
            .ForManageableUser()
            .WithName("SendUserActionsEmail")
            .Produces(202).ProducesProblem(400).ProducesProblem(404).ProducesProblem(502);

        return app;
    }
}
