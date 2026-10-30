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

        static IResult ValidationError(ScopedValidationException ex)
            => Results.ValidationProblem(ex.Errors, title: "One or more validation errors occurred.", statusCode: 400);

        g.MapPost("", async (CreateUserRequest req, ProvisioningOrchestrator orch, CancellationToken ct) =>
            {
                if (string.IsNullOrWhiteSpace(req.Username))
                    return Error.Validation("request.invalid", "username is required").ToProblem();
                try
                {
                    var (user, _) = await orch.CreateUserWithAssignmentsAsync(req, ct);
                    return Results.Created($"/api/identity/users/{Uri.EscapeDataString(user.Id)}", user);
                }
                catch (ScopedValidationException ex) { return ValidationError(ex); }
                catch (InvalidOperationException ex)
                {
                    return Error.Validation("request.invalid", ex.Message).ToProblem();
                }
            }).RequireAuthorization(IamPermissions.UsersManage)
            .WithName("CreateUserWithAccess")
            .Produces<UserDto>(201).ProducesProblem(400);

        g.MapPut("/{id}", async (string id, UpdateUserRequest req, IUserProvisioningService svc, CancellationToken ct) =>
            {
                var protectedKeys = ProtectedUserAttributes.FindIn(req.Attributes);
                if (protectedKeys.Count > 0)
                    return Error.Validation("request.invalid", $"Attributes {string.Join(", ", protectedKeys)} are managed by the gateway; use the scoped-access APIs instead.").ToProblem();

                var updated = await svc.UpdateUserAsync(id, req, ct);
                return updated is null
                    ? Error.NotFound("resource.not_found", $"user '{id}' not found").ToProblem()
                    : Results.Ok(updated);
            }).RequireAuthorization(IamPermissions.UsersManage)
            .WithName("UpdateUserWithAccess")
            .Produces<UserDto>(200);

        g.MapDelete("/{id}", async (string id, IUserProvisioningService svc, IUserDirectory dir, CancellationToken ct) =>
            {
                var user = await dir.GetUserAsync(id, ct);
                if (user is null)
                    return Error.NotFound("resource.not_found", $"user '{id}' not found").ToProblem();
                var ok = await svc.DeleteUserAsync(id, ct);
                return ok ? Results.NoContent() : Results.Problem("Failed to delete user", statusCode: 500);
            }).RequireAuthorization(IamPermissions.UsersManage)
            .WithName("DeleteUser")
            .Produces(204).ProducesProblem(404);

        g.MapPut("/{id}/reset-password", async (string id, ResetPasswordRequest req, IUserProvisioningService svc, IUserDirectory dir, CancellationToken ct) =>
            {
                if (string.IsNullOrWhiteSpace(req.Password))
                    return Error.Validation("request.invalid", "password is required").ToProblem();
                var user = await dir.GetUserAsync(id, ct);
                if (user is null)
                    return Error.NotFound("resource.not_found", $"user '{id}' not found").ToProblem();
                var ok = await svc.ResetPasswordAsync(id, req.Password, req.Temporary, ct);
                return ok ? Results.NoContent() : Results.Problem("Failed to reset password", statusCode: 500);
            }).RequireAuthorization(IamPermissions.UsersManage)
            .WithName("ResetUserPassword")
            .Produces(204).ProducesProblem(400).ProducesProblem(404);

        g.MapPost("/{id}/reset-password", async (string id, ResetPasswordRequest req, IUserProvisioningService svc, IUserDirectory dir, CancellationToken ct) =>
            {
                if (string.IsNullOrWhiteSpace(req.Password))
                    return Error.Validation("request.invalid", "password is required").ToProblem();
                var user = await dir.GetUserAsync(id, ct);
                if (user is null)
                    return Error.NotFound("resource.not_found", $"user '{id}' not found").ToProblem();
                var ok = await svc.ResetPasswordAsync(id, req.Password, req.Temporary, ct);
                return ok ? Results.NoContent() : Results.Problem("Failed to reset password", statusCode: 500);
            }).RequireAuthorization(IamPermissions.UsersManage)
            .WithName("ResetUserPasswordPost")
            .Produces(204).ProducesProblem(400).ProducesProblem(404);

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

        g.MapPut("/{id}/scoped-access", async (string id, SetScopedAccessRequest req, ProvisioningOrchestrator orch, IUserDirectory dir, CancellationToken ct) =>
            {
                if (await dir.GetUserAsync(id, ct) is null)
                    return Error.NotFound("resource.not_found", $"user '{id}' not found").ToProblem();
                try
                {
                    var doc = await orch.ReplaceAssignmentsAsync(id, req.Assignments, ct);
                    return Results.Ok(new ScopedAccessResponse(id, doc.Assignments.ToArray()));
                }
                catch (ScopedValidationException ex) { return ValidationError(ex); }
                catch (InvalidOperationException ex)
                {
                    return Error.Validation("request.invalid", ex.Message).ToProblem();
                }
            }).RequireAuthorization(IamPermissions.ScopesManage)
            .WithName("SetScopedAccess")
            .Produces<ScopedAccessResponse>(200);

        g.MapPost("/{id}/scoped-assignments", async (string id, ScopedRoleAssignmentDto req, ProvisioningOrchestrator orch, IUserDirectory dir, CancellationToken ct) =>
            {
                if (string.IsNullOrWhiteSpace(req.Role))
                    return Error.Validation("request.invalid", "role is required").ToProblem();
                if (await dir.GetUserAsync(id, ct) is null)
                    return Error.NotFound("resource.not_found", $"user '{id}' not found").ToProblem();
                try
                {
                    var doc = await orch.AddScopedAssignmentAsync(id, req, ct);
                    return Results.Ok(new ScopedAccessResponse(id, doc.Assignments.ToArray()));
                }
                catch (ScopedValidationException ex) { return ValidationError(ex); }
                catch (InvalidOperationException ex)
                {
                    return Error.Validation("request.invalid", ex.Message).ToProblem();
                }
            }).RequireAuthorization(IamPermissions.ScopesManage)
            .WithName("AddScopedAssignment")
            .Produces<ScopedAccessResponse>(200);

        g.MapPut("/{id}/scoped-assignments/{role}", async (string id, string role, Dictionary<string, IReadOnlyCollection<string>> scopes, IScopedAccessStore store, IBusinessRoleStore roles, IUserDirectory dir, CancellationToken ct) =>
            {
                if (await dir.GetUserAsync(id, ct) is null)
                    return Error.NotFound("resource.not_found", $"user '{id}' not found").ToProblem();
                if (await roles.GetAsync(role, ct) is null)
                    return Error.Validation("request.invalid", $"Role '{role}' does not exist.").ToProblem();
                try
                {
                    var dict = (IReadOnlyDictionary<string, IReadOnlyCollection<string>>)(scopes ?? new Dictionary<string, IReadOnlyCollection<string>>(StringComparer.Ordinal));
                    await store.UpdateAssignmentAsync(id, role, dict, ct);
                    var doc = await store.GetAsync(id, ct);
                    return Results.Ok(new ScopedAccessResponse(id, doc.Assignments.ToArray()));
                }
                catch (InvalidOperationException ex)
                {
                    return Error.Validation("request.invalid", ex.Message).ToProblem();
                }
            }).RequireAuthorization(IamPermissions.ScopesManage)
            .WithName("UpdateScopedAssignment")
            .Produces<ScopedAccessResponse>(200);

        g.MapDelete("/{id}/scoped-assignments/{role}", async (string id, string role, ProvisioningOrchestrator orch, IUserDirectory dir, CancellationToken ct) =>
            {
                if (await dir.GetUserAsync(id, ct) is null)
                    return Error.NotFound("resource.not_found", $"user '{id}' not found").ToProblem();
                await orch.RemoveScopedAssignmentAsync(id, role, ct);
                return Results.NoContent();
            }).RequireAuthorization(IamPermissions.ScopesManage)
            .WithName("RemoveScopedAssignment")
            .Produces(204);

        return g;
    }
}
