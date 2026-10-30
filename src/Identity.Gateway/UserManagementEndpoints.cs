#pragma warning disable ASPDEPR002
using Avash.Identity.Abstractions;
using Identity.Application;
using Identity.Application.Scope;
using Identity.Contracts;
using Identity.Gateway.Errors;

namespace Identity.Gateway;

public static class UserManagementEndpoints
{
    public static RouteGroupBuilder MapUserManagement(this IEndpointRouteBuilder app)
    {
        var g = app.MapGroup("/api/identity/users").WithTags("Users");

        g.MapPost("", async (CreateUserRequest req, ProvisioningOrchestrator orch, CancellationToken ct) =>
                (await orch.CreateUserWithAssignmentsAsync(req, ct)).ToHttpResult(created =>
                    Results.Created($"/api/identity/users/{Uri.EscapeDataString(created.User.Id)}", created.User)))
            .WithValidation<CreateUserRequest>()
            .RequireAuthorization(IamPermissions.UsersManage)
            .WithName("CreateUserWithAccess")
            .Produces<UserDto>(201).ProducesProblem(400).ProducesProblem(409);

        g.MapPut("/{id}", async (string id, UpdateUserRequest req, IUserProvisioningService svc, CancellationToken ct) =>
                (await svc.UpdateUserAsync(id, req, ct)).ToHttpResult(user => Results.Ok(user)))
            .WithValidation<UpdateUserRequest>()
            .RequireAuthorization(IamPermissions.UsersManage)
            .WithName("UpdateUserWithAccess")
            .Produces<UserDto>(200).ProducesProblem(400).ProducesProblem(404).ProducesProblem(409);

        g.MapDelete("/{id}", async (string id, IUserProvisioningService svc, CancellationToken ct) =>
                (await svc.DeleteUserAsync(id, ct)).ToHttpResult(() => Results.NoContent()))
            .RequireAuthorization(IamPermissions.UsersManage)
            .WithName("DeleteUser")
            .Produces(204).ProducesProblem(404);

        // PUT is the canonical route; POST is kept for existing clients.
        foreach (var (method, name) in new[] { ("PUT", "ResetUserPassword"), ("POST", "ResetUserPasswordPost") })
        {
            g.MapMethods("/{id}/reset-password", [method], async (string id, ResetPasswordRequest req,
                        IUserProvisioningService svc, CancellationToken ct) =>
                    (await svc.ResetPasswordAsync(id, req.Password, req.Temporary, ct)).ToHttpResult(() => Results.NoContent()))
                .WithValidation<ResetPasswordRequest>()
                .RequireAuthorization(IamPermissions.UsersManage)
                .WithName(name)
                .Produces(204).ProducesProblem(400).ProducesProblem(404);
        }

        g.MapGet("/{id}/sessions", async (string id, IUserSessionService sessionService, IUserDirectory dir, CancellationToken ct) =>
            {
                var user = await dir.GetUserAsync(id, ct);
                if (user is null)
                    return Error.NotFound("resource.not_found", $"user '{id}' not found").ToProblem();
                var sessions = await sessionService.GetUserSessionsAsync(id, ct);
                return Results.Ok(sessions);
            }).RequireAuthorization(IamPermissions.UsersManage)
            .WithName("GetUserSessions")
            .Produces<IReadOnlyCollection<UserSessionDto>>(200);

        g.MapPost("/{id}/revoke", async (string id, RevokeUserTokensRequest? req, IUserSessionService sessionService, IUserDirectory dir, CancellationToken ct) =>
            {
                var user = await dir.GetUserAsync(id, ct);
                if (user is null)
                    return Error.NotFound("resource.not_found", $"user '{id}' not found").ToProblem();
                var res = await sessionService.RevokeUserTokensAsync(id, req?.Reason, ct);
                return Results.Ok(res);
            }).RequireAuthorization(IamPermissions.UsersManage)
            .WithName("RevokeUserTokens")
            .Produces<RevokeUserTokensResponse>(200);

        g.MapGet("/{id}/scoped-access", async (string id, IScopedAccessStore store, IUserDirectory dir, CancellationToken ct) =>
            {
                var user = await dir.GetUserAsync(id, ct);
                if (user is null) return Error.NotFound("resource.not_found", $"user '{id}' not found").ToProblem();
                var doc = await store.GetAsync(id, ct);
                return Results.Ok(new ScopedAccessResponse(id, doc.Assignments.ToArray()));
            }).RequireAuthorization(IamPermissions.ScopesRead)
            .WithName("GetScopedAccess")
            .Produces<ScopedAccessResponse>(200);

        g.MapPut("/{id}/scoped-access", async (string id, SetScopedAccessRequest req, ProvisioningOrchestrator orch, CancellationToken ct) =>
                (await orch.ReplaceAssignmentsAsync(id, req.Assignments, ct))
                .ToHttpResult(doc => Results.Ok(new ScopedAccessResponse(id, doc.Assignments.ToArray()))))
            .RequireAuthorization(IamPermissions.ScopesManage)
            .WithName("SetScopedAccess")
            .Produces<ScopedAccessResponse>(200).ProducesProblem(400).ProducesProblem(404);

        g.MapPost("/{id}/scoped-assignments", async (string id, ScopedRoleAssignmentDto req, ProvisioningOrchestrator orch, CancellationToken ct) =>
                (await orch.AddScopedAssignmentAsync(id, req, ct))
                .ToHttpResult(doc => Results.Ok(new ScopedAccessResponse(id, doc.Assignments.ToArray()))))
            .WithValidation<ScopedRoleAssignmentDto>()
            .RequireAuthorization(IamPermissions.ScopesManage)
            .WithName("AddScopedAssignment")
            .Produces<ScopedAccessResponse>(200).ProducesProblem(400).ProducesProblem(404);

        g.MapPut("/{id}/scoped-assignments/{role}", async (string id, string role,
                Dictionary<string, IReadOnlyCollection<string>>? scopes, ProvisioningOrchestrator orch, CancellationToken ct) =>
                (await orch.UpdateScopedAssignmentAsync(id, role,
                    scopes ?? new Dictionary<string, IReadOnlyCollection<string>>(StringComparer.Ordinal), ct))
                .ToHttpResult(doc => Results.Ok(new ScopedAccessResponse(id, doc.Assignments.ToArray()))))
            .RequireAuthorization(IamPermissions.ScopesManage)
            .WithName("UpdateScopedAssignment")
            .Produces<ScopedAccessResponse>(200).ProducesProblem(400).ProducesProblem(404);

        g.MapDelete("/{id}/scoped-assignments/{role}", async (string id, string role, ProvisioningOrchestrator orch, CancellationToken ct) =>
                (await orch.RemoveScopedAssignmentAsync(id, role, ct)).ToHttpResult(() => Results.NoContent()))
            .RequireAuthorization(IamPermissions.ScopesManage)
            .WithName("RemoveScopedAssignment")
            .Produces(204).ProducesProblem(404);

        return g;
    }
}
