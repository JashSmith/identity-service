#pragma warning disable ASPDEPR002
using Avash.Identity.Abstractions;
using Identity.Application;
using Identity.Application.Scope;
using Identity.Contracts;

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
                    return Results.BadRequest(new ProblemResponse("validation_error", "username is required", Guid.NewGuid().ToString("N")));
                try
                {
                    var (user, _) = await orch.CreateUserWithAssignmentsAsync(req, ct);
                    return Results.Created($"/api/identity/users/{Uri.EscapeDataString(user.Id)}", user);
                }
                catch (ScopedValidationException ex) { return ValidationError(ex); }
                catch (InvalidOperationException ex)
                {
                    return Results.BadRequest(new ProblemResponse("validation_error", ex.Message, Guid.NewGuid().ToString("N")));
                }
            }).RequireAuthorization(IamPermissions.UsersManage)
            .WithName("CreateUserWithAccess")
            .Produces<UserDto>(201).Produces<ProblemResponse>(400);

        g.MapPut("/{id}", async (string id, UpdateUserRequest req, IUserProvisioningService svc, CancellationToken ct) =>
            {
                var protectedKeys = ProtectedUserAttributes.FindIn(req.Attributes);
                if (protectedKeys.Count > 0)
                    return Results.BadRequest(new ProblemResponse("validation_error",
                        $"Attributes {string.Join(", ", protectedKeys)} are managed by the gateway; use the scoped-access APIs instead.",
                        Guid.NewGuid().ToString("N")));

                var updated = await svc.UpdateUserAsync(id, req, ct);
                return updated is null
                    ? Results.NotFound(new ProblemResponse("not_found", $"user '{id}' not found", Guid.NewGuid().ToString("N")))
                    : Results.Ok(updated);
            }).RequireAuthorization(IamPermissions.UsersManage)
            .WithName("UpdateUserWithAccess")
            .Produces<UserDto>(200);

        g.MapDelete("/{id}", async (string id, IUserProvisioningService svc, IUserDirectory dir, CancellationToken ct) =>
            {
                var user = await dir.GetUserAsync(id, ct);
                if (user is null)
                    return Results.NotFound(new ProblemResponse("not_found", $"user '{id}' not found", Guid.NewGuid().ToString("N")));
                var ok = await svc.DeleteUserAsync(id, ct);
                return ok ? Results.NoContent() : Results.Problem("Failed to delete user", statusCode: 500);
            }).RequireAuthorization(IamPermissions.UsersManage)
            .WithName("DeleteUser")
            .Produces(204).Produces<ProblemResponse>(404);

        g.MapPut("/{id}/reset-password", async (string id, ResetPasswordRequest req, IUserProvisioningService svc, IUserDirectory dir, CancellationToken ct) =>
            {
                if (string.IsNullOrWhiteSpace(req.Password))
                    return Results.BadRequest(new ProblemResponse("validation_error", "password is required", Guid.NewGuid().ToString("N")));
                var user = await dir.GetUserAsync(id, ct);
                if (user is null)
                    return Results.NotFound(new ProblemResponse("not_found", $"user '{id}' not found", Guid.NewGuid().ToString("N")));
                var ok = await svc.ResetPasswordAsync(id, req.Password, req.Temporary, ct);
                return ok ? Results.NoContent() : Results.Problem("Failed to reset password", statusCode: 500);
            }).RequireAuthorization(IamPermissions.UsersManage)
            .WithName("ResetUserPassword")
            .Produces(204).Produces<ProblemResponse>(400).Produces<ProblemResponse>(404);

        g.MapPost("/{id}/reset-password", async (string id, ResetPasswordRequest req, IUserProvisioningService svc, IUserDirectory dir, CancellationToken ct) =>
            {
                if (string.IsNullOrWhiteSpace(req.Password))
                    return Results.BadRequest(new ProblemResponse("validation_error", "password is required", Guid.NewGuid().ToString("N")));
                var user = await dir.GetUserAsync(id, ct);
                if (user is null)
                    return Results.NotFound(new ProblemResponse("not_found", $"user '{id}' not found", Guid.NewGuid().ToString("N")));
                var ok = await svc.ResetPasswordAsync(id, req.Password, req.Temporary, ct);
                return ok ? Results.NoContent() : Results.Problem("Failed to reset password", statusCode: 500);
            }).RequireAuthorization(IamPermissions.UsersManage)
            .WithName("ResetUserPasswordPost")
            .Produces(204).Produces<ProblemResponse>(400).Produces<ProblemResponse>(404);

        g.MapGet("/{id}/sessions", async (string id, IUserSessionService sessionService, IUserDirectory dir, CancellationToken ct) =>
            {
                var user = await dir.GetUserAsync(id, ct);
                if (user is null)
                    return Results.NotFound(new ProblemResponse("not_found", $"user '{id}' not found", Guid.NewGuid().ToString("N")));
                var sessions = await sessionService.GetUserSessionsAsync(id, ct);
                return Results.Ok(sessions);
            }).RequireAuthorization(IamPermissions.UsersManage)
            .WithName("GetUserSessions")
            .Produces<IReadOnlyCollection<UserSessionDto>>(200);

        g.MapPost("/{id}/revoke", async (string id, RevokeUserTokensRequest? req, IUserSessionService sessionService, IUserDirectory dir, CancellationToken ct) =>
            {
                var user = await dir.GetUserAsync(id, ct);
                if (user is null)
                    return Results.NotFound(new ProblemResponse("not_found", $"user '{id}' not found", Guid.NewGuid().ToString("N")));
                var res = await sessionService.RevokeUserTokensAsync(id, req?.Reason, ct);
                return Results.Ok(res);
            }).RequireAuthorization(IamPermissions.UsersManage)
            .WithName("RevokeUserTokens")
            .Produces<RevokeUserTokensResponse>(200);

        g.MapGet("/{id}/scoped-access", async (string id, IScopedAccessStore store, IUserDirectory dir, CancellationToken ct) =>
            {
                var user = await dir.GetUserAsync(id, ct);
                if (user is null) return Results.NotFound(new ProblemResponse("not_found", $"user '{id}' not found", Guid.NewGuid().ToString("N")));
                var doc = await store.GetAsync(id, ct);
                return Results.Ok(new ScopedAccessResponse(id, doc.Assignments.ToArray()));
            }).RequireAuthorization(IamPermissions.ScopesRead)
            .WithName("GetScopedAccess")
            .Produces<ScopedAccessResponse>(200);

        g.MapPut("/{id}/scoped-access", async (string id, SetScopedAccessRequest req, ProvisioningOrchestrator orch, IUserDirectory dir, CancellationToken ct) =>
            {
                if (await dir.GetUserAsync(id, ct) is null)
                    return Results.NotFound(new ProblemResponse("not_found", $"user '{id}' not found", Guid.NewGuid().ToString("N")));
                try
                {
                    var doc = await orch.ReplaceAssignmentsAsync(id, req.Assignments, ct);
                    return Results.Ok(new ScopedAccessResponse(id, doc.Assignments.ToArray()));
                }
                catch (ScopedValidationException ex) { return ValidationError(ex); }
                catch (InvalidOperationException ex)
                {
                    return Results.BadRequest(new ProblemResponse("validation_error", ex.Message, Guid.NewGuid().ToString("N")));
                }
            }).RequireAuthorization(IamPermissions.ScopesManage)
            .WithName("SetScopedAccess")
            .Produces<ScopedAccessResponse>(200);

        g.MapPost("/{id}/scoped-assignments", async (string id, ScopedRoleAssignmentDto req, ProvisioningOrchestrator orch, IUserDirectory dir, CancellationToken ct) =>
            {
                if (string.IsNullOrWhiteSpace(req.Role))
                    return Results.BadRequest(new ProblemResponse("validation_error", "role is required", Guid.NewGuid().ToString("N")));
                if (await dir.GetUserAsync(id, ct) is null)
                    return Results.NotFound(new ProblemResponse("not_found", $"user '{id}' not found", Guid.NewGuid().ToString("N")));
                try
                {
                    var doc = await orch.AddScopedAssignmentAsync(id, req, ct);
                    return Results.Ok(new ScopedAccessResponse(id, doc.Assignments.ToArray()));
                }
                catch (ScopedValidationException ex) { return ValidationError(ex); }
                catch (InvalidOperationException ex)
                {
                    return Results.BadRequest(new ProblemResponse("validation_error", ex.Message, Guid.NewGuid().ToString("N")));
                }
            }).RequireAuthorization(IamPermissions.ScopesManage)
            .WithName("AddScopedAssignment")
            .Produces<ScopedAccessResponse>(200);

        g.MapPut("/{id}/scoped-assignments/{role}", async (string id, string role, Dictionary<string, IReadOnlyCollection<string>> scopes, IScopedAccessStore store, IBusinessRoleStore roles, IUserDirectory dir, CancellationToken ct) =>
            {
                if (await dir.GetUserAsync(id, ct) is null)
                    return Results.NotFound(new ProblemResponse("not_found", $"user '{id}' not found", Guid.NewGuid().ToString("N")));
                if (await roles.GetAsync(role, ct) is null)
                    return Results.BadRequest(new ProblemResponse("validation_error", $"Role '{role}' does not exist.", Guid.NewGuid().ToString("N")));
                try
                {
                    var dict = (IReadOnlyDictionary<string, IReadOnlyCollection<string>>)(scopes ?? new Dictionary<string, IReadOnlyCollection<string>>(StringComparer.Ordinal));
                    await store.UpdateAssignmentAsync(id, role, dict, ct);
                    var doc = await store.GetAsync(id, ct);
                    return Results.Ok(new ScopedAccessResponse(id, doc.Assignments.ToArray()));
                }
                catch (InvalidOperationException ex)
                {
                    return Results.BadRequest(new ProblemResponse("validation_error", ex.Message, Guid.NewGuid().ToString("N")));
                }
            }).RequireAuthorization(IamPermissions.ScopesManage)
            .WithName("UpdateScopedAssignment")
            .Produces<ScopedAccessResponse>(200);

        g.MapDelete("/{id}/scoped-assignments/{role}", async (string id, string role, ProvisioningOrchestrator orch, IUserDirectory dir, CancellationToken ct) =>
            {
                if (await dir.GetUserAsync(id, ct) is null)
                    return Results.NotFound(new ProblemResponse("not_found", $"user '{id}' not found", Guid.NewGuid().ToString("N")));
                await orch.RemoveScopedAssignmentAsync(id, role, ct);
                return Results.NoContent();
            }).RequireAuthorization(IamPermissions.ScopesManage)
            .WithName("RemoveScopedAssignment")
            .Produces(204);

        return g;
    }
}
