using Identity.Application;
using Identity.Contracts;

namespace Identity.Gateway.Tests;

/// <summary>
/// User creation and assignment changes keep scopes and role memberships consistent, and undo
/// completed steps when a later one fails.
/// </summary>
public sealed class ProvisioningOrchestratorTests
{
    private static readonly CancellationToken Ct = CancellationToken.None;

    private sealed class Users : IUserProvisioningService
    {
        public Dictionary<string, UserDto> All { get; } = new();
        public Error? CreateFails { get; set; }

        public Task<Result<UserDto>> GetAsync(string userId, CancellationToken ct) =>
            Task.FromResult(All.TryGetValue(userId, out var u)
                ? Result<UserDto>.Success(u)
                : Error.NotFound("user.not_found", userId));

        public Task<Result<UserDto>> CreateUserAsync(CreateUserRequest request, CancellationToken ct)
        {
            if (CreateFails is not null) return Task.FromResult(Result<UserDto>.Failure(CreateFails));
            var user = new UserDto("u-" + request.Username, request.Username, null, true, new Dictionary<string, string[]>());
            All[user.Id] = user;
            return Task.FromResult(Result<UserDto>.Success(user));
        }

        public Task<Result<UserDto>> UpdateUserAsync(string userId, UpdateUserRequest request, CancellationToken ct) => GetAsync(userId, ct);

        public Task<Result> DeleteUserAsync(string userId, CancellationToken ct) =>
            Task.FromResult(All.Remove(userId) ? Result.Success() : Result.Failure(Error.NotFound("user.not_found", userId)));

        public Task<Result> ResetPasswordAsync(string userId, string newPassword, bool temporary, CancellationToken ct) =>
            Task.FromResult(Result.Success());
    }

    private sealed class Scopes : IScopedAccessStore
    {
        public Dictionary<string, ScopedAccessDocument> Docs { get; } = new();

        public Task<ScopedAccessDocument> GetAsync(string userId, CancellationToken ct) =>
            Task.FromResult(Docs.GetValueOrDefault(userId, ScopedAccessDocument.Empty));

        public Task SetAsync(string userId, ScopedAccessDocument document, CancellationToken ct)
        {
            Docs[userId] = document;
            return Task.CompletedTask;
        }

        public Task AddAssignmentAsync(string userId, ScopedRoleAssignmentDto assignment, CancellationToken ct) => throw new NotSupportedException();
        public Task UpdateAssignmentAsync(string userId, string role, IReadOnlyDictionary<string, IReadOnlyCollection<string>> scopes, CancellationToken ct) => Task.CompletedTask;
        public Task RemoveAssignmentAsync(string userId, string role, CancellationToken ct) => throw new NotSupportedException();
    }

    private sealed class Membership : IUserRoleMapping
    {
        public HashSet<(string User, string Role)> Members { get; } = [];
        public HashSet<string> FailingRoles { get; } = new(StringComparer.Ordinal);

        public Task<Result> AssignRoleAsync(string userId, string roleName, CancellationToken ct) =>
            Change(() => Members.Add((userId, roleName)), roleName);

        public Task<Result> UnassignRoleAsync(string userId, string roleName, CancellationToken ct) =>
            Change(() => Members.Remove((userId, roleName)), roleName);

        private Task<Result> Change(Action apply, string role)
        {
            if (FailingRoles.Contains(role))
                return Task.FromResult(Result.Failure(Error.Unavailable("keycloak.unreachable", "down")));
            apply();
            return Task.FromResult(Result.Success());
        }
    }

    private sealed class Roles(params string[] names) : IBusinessRoleStore
    {
        private static BusinessRoleDto Dto(string n) => new(n, null, true, Array.Empty<string>());
        public Task<Result<BusinessRoleDto>> GetAsync(string name, CancellationToken ct) =>
            Task.FromResult(names.Contains(name) ? Result<BusinessRoleDto>.Success(Dto(name)) : Error.NotFound("role.not_found", name));
        public Task<Result<IReadOnlyCollection<BusinessRoleDto>>> ListAsync(CancellationToken ct) => throw new NotSupportedException();
        public Task<Result<BusinessRoleDto>> CreateAsync(string name, string? description, IReadOnlyCollection<string> permissions, CancellationToken ct) => throw new NotSupportedException();
        public Task<Result<BusinessRoleDto>> UpdateAsync(string name, string? description, CancellationToken ct) => throw new NotSupportedException();
        public Task<Result> DeleteAsync(string name, CancellationToken ct) => throw new NotSupportedException();
        public Task<Result<IReadOnlyCollection<string>>> GetEffectivePermissionsAsync(string name, CancellationToken ct) => throw new NotSupportedException();
        public Task<Result> AddPermissionsAsync(string name, IReadOnlyCollection<string> permissions, CancellationToken ct) => throw new NotSupportedException();
        public Task<Result> RemovePermissionAsync(string name, string permission, CancellationToken ct) => throw new NotSupportedException();
        public Task<Result> SetPermissionsAsync(string name, IReadOnlyCollection<string> permissions, CancellationToken ct) => throw new NotSupportedException();
    }

    private static ScopedRoleAssignmentDto Assignment(string role, string region = "tehran") =>
        new(role, new Dictionary<string, IReadOnlyCollection<string>> { ["region"] = [region] });

    private static CreateUserRequest NewUser(params ScopedRoleAssignmentDto[] assignments) =>
        new("ali", "ali@test.local", "Ali", "R", true, new CredentialRequest("P@ss-word-1", false), assignments);

    private sealed record Fixture(Users Users, Scopes Scopes, Membership Membership, ProvisioningOrchestrator Orchestrator);

    private static Fixture Create(params string[] roles)
    {
        var users = new Users();
        var scopes = new Scopes();
        var membership = new Membership();
        return new Fixture(users, scopes, membership,
            new ProvisioningOrchestrator(users, scopes, new Roles(roles), membership));
    }

    [Fact]
    public async Task Created_user_gets_scopes_and_role_membership()
    {
        var f = Create("Accountant");

        var created = await f.Orchestrator.CreateUserWithAssignmentsAsync(NewUser(Assignment("Accountant")), Ct);

        Assert.True(created.IsSuccess);
        Assert.Contains(("u-ali", "Accountant"), f.Membership.Members);
        Assert.Equal("Accountant", Assert.Single(f.Scopes.Docs["u-ali"].Assignments).Role);
    }

    [Fact]
    public async Task User_is_removed_again_when_role_membership_fails()
    {
        var f = Create("Accountant", "Inspector");
        f.Membership.FailingRoles.Add("Inspector");

        var created = await f.Orchestrator.CreateUserWithAssignmentsAsync(
            NewUser(Assignment("Accountant"), Assignment("Inspector")), Ct);

        Assert.Equal("keycloak.unreachable", created.Error?.Code);
        Assert.Empty(f.Users.All);
        Assert.Empty(f.Membership.Members);
    }

    [Fact]
    public async Task Unknown_role_creates_nothing()
    {
        var f = Create("Accountant");

        var created = await f.Orchestrator.CreateUserWithAssignmentsAsync(NewUser(Assignment("Ghost")), Ct);

        Assert.Equal("role.not_found", created.Error?.Code);
        Assert.Empty(f.Users.All);
    }

    [Fact]
    public async Task Empty_scope_value_is_a_validation_error_not_a_crash()
    {
        var f = Create("Accountant");
        var bad = new ScopedRoleAssignmentDto("Accountant",
            new Dictionary<string, IReadOnlyCollection<string>> { ["region"] = [" "] });

        var created = await f.Orchestrator.CreateUserWithAssignmentsAsync(NewUser(bad), Ct);

        Assert.Equal(ErrorKind.Validation, created.Error?.Kind);
        Assert.Empty(f.Users.All);
    }

    [Fact]
    public async Task Failed_replace_restores_previous_roles_and_scopes()
    {
        var f = Create("Accountant", "Inspector", "Auditor");
        await f.Orchestrator.CreateUserWithAssignmentsAsync(NewUser(Assignment("Accountant")), Ct);
        var before = f.Scopes.Docs["u-ali"];
        f.Membership.FailingRoles.Add("Auditor");

        var replaced = await f.Orchestrator.ReplaceAssignmentsAsync("u-ali",
            [Assignment("Inspector", "shiraz"), Assignment("Auditor")], Ct);

        Assert.False(replaced.IsSuccess);
        Assert.Equal([("u-ali", "Accountant")], f.Membership.Members);
        Assert.Same(before, f.Scopes.Docs["u-ali"]);
    }

    [Fact]
    public async Task Replace_moves_memberships_to_the_new_roles()
    {
        var f = Create("Accountant", "Inspector");
        await f.Orchestrator.CreateUserWithAssignmentsAsync(NewUser(Assignment("Accountant")), Ct);

        var replaced = await f.Orchestrator.ReplaceAssignmentsAsync("u-ali", [Assignment("Inspector")], Ct);

        Assert.True(replaced.IsSuccess);
        Assert.Equal([("u-ali", "Inspector")], f.Membership.Members);
    }

    [Fact]
    public async Task Assignments_for_unknown_user_are_user_not_found()
    {
        var f = Create("Accountant");

        var added = await f.Orchestrator.AddScopedAssignmentAsync("nobody", Assignment("Accountant"), Ct);

        Assert.Equal("user.not_found", added.Error?.Code);
        Assert.Empty(f.Membership.Members);
    }

    [Fact]
    public async Task Removing_an_assignment_drops_the_membership()
    {
        var f = Create("Accountant");
        await f.Orchestrator.CreateUserWithAssignmentsAsync(NewUser(Assignment("Accountant")), Ct);

        var removed = await f.Orchestrator.RemoveScopedAssignmentAsync("u-ali", "Accountant", Ct);

        Assert.True(removed.IsSuccess);
        Assert.Empty(f.Membership.Members);
        Assert.Empty(f.Scopes.Docs["u-ali"].Assignments);
    }

    [Theory]
    [InlineData("ali", "ali@test.local", true)]
    [InlineData("", null, false)]
    [InlineData("ali reza", null, false)]
    [InlineData("ali", "not-an-email", false)]
    public void Create_user_requests_are_validated(string username, string? email, bool valid)
    {
        var result = new Identity.Application.Users.CreateUserRequestValidator()
            .Validate(new CreateUserRequest(username, email, null, null, true, null, null));

        Assert.Equal(valid, result.IsValid);
    }

    [Fact]
    public void Update_request_with_scope_attribute_is_invalid()
    {
        var result = new Identity.Application.Users.UpdateUserRequestValidator().Validate(new UpdateUserRequest(
            null, null, null, null, Attributes: new Dictionary<string, string[]> { ["authz.scope.region"] = ["*"] }));

        Assert.False(result.IsValid);
        Assert.Contains("authz.scope.region", result.Errors[0].ErrorMessage);
    }
}
