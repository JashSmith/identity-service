using Identity.Application;
using Identity.Application.Scope;
using Identity.Contracts;

namespace Identity.Gateway.Tests;

/// <summary>Delegated administrators only grant what they hold and only act inside their own scope.</summary>
public sealed class DelegationGuardTests
{
    private static readonly CancellationToken Ct = CancellationToken.None;

    private sealed class Admin(string? userId, bool superAdmin, params string[] permissions) : ICurrentAdministrator
    {
        public string? UserId => userId;
        public IReadOnlyCollection<string> Permissions => permissions;
        public Task<Result<bool>> IsSuperAdminAsync(CancellationToken ct) => Task.FromResult(Result<bool>.Success(superAdmin));
    }

    private sealed class EffectiveScopes : IUserScopeReader
    {
        public Dictionary<string, Dictionary<string, IReadOnlyCollection<string>>> Users { get; } = new();

        public Task<Result<ScopedAccessDocument>> GetAsync(string userId, CancellationToken ct) => throw new NotSupportedException();

        public Task<Result<IReadOnlyDictionary<string, IReadOnlyCollection<string>>>> GetEffectiveAsync(string userId, CancellationToken ct) =>
            Task.FromResult(Result<IReadOnlyDictionary<string, IReadOnlyCollection<string>>>.Success(
                Users.GetValueOrDefault(userId) ?? new Dictionary<string, IReadOnlyCollection<string>>()));
    }

    private sealed class Roles(Dictionary<string, string[]> permissions) : IBusinessRoleStore
    {
        public Task<Result<BusinessRoleDto>> GetAsync(string name, CancellationToken ct) =>
            Task.FromResult(permissions.TryGetValue(name, out var p)
                ? Result<BusinessRoleDto>.Success(new BusinessRoleDto(name, null, true, p))
                : Error.NotFound("role.not_found", name));
        public Task<Result<IReadOnlyCollection<BusinessRoleDto>>> ListAsync(CancellationToken ct) => throw new NotSupportedException();
        public Task<Result<BusinessRoleDto>> CreateAsync(string name, string? description, IReadOnlyCollection<string> permissions, RoleScopePolicy? scopePolicy, CancellationToken ct) => throw new NotSupportedException();
        public Task<Result<BusinessRoleDto>> UpdateAsync(string name, string? description, CancellationToken ct) => throw new NotSupportedException();
        public Task<Result> DeleteAsync(string name, CancellationToken ct) => throw new NotSupportedException();
        public Task<Result<IReadOnlyCollection<string>>> GetEffectivePermissionsAsync(string name, CancellationToken ct) => throw new NotSupportedException();
        public Task<Result> AddPermissionsAsync(string name, IReadOnlyCollection<string> permissions, CancellationToken ct) => throw new NotSupportedException();
        public Task<Result> RemovePermissionAsync(string name, string permission, CancellationToken ct) => throw new NotSupportedException();
        public Task<Result> SetPermissionsAsync(string name, IReadOnlyCollection<string> permissions, CancellationToken ct) => throw new NotSupportedException();
        public Task<Result> SetScopePolicyAsync(string name, RoleScopePolicy policy, CancellationToken ct) => throw new NotSupportedException();
    }

    private static readonly Dictionary<string, string[]> RolePermissions = new()
    {
        ["Clerk"] = ["orders:Sales:Order:Read"],
        ["Approver"] = ["orders:Sales:Order:Approve"],
    };

    private static (DelegationGuard Guard, EffectiveScopes Scopes) Create(ICurrentAdministrator admin)
    {
        var scopes = new EffectiveScopes();
        scopes.Users["tehran-admin"] = new() { ["province"] = ["tehran"], ["district"] = ["*"] };
        scopes.Users["tehran-user"] = new() { ["province"] = ["tehran"] };
        scopes.Users["shiraz-user"] = new() { ["province"] = ["fars"] };
        return (new DelegationGuard(admin, scopes, new Roles(RolePermissions)), scopes);
    }

    private static ScopedRoleAssignmentDto Assign(string role, params string[] provinces) =>
        new(role, new Dictionary<string, IReadOnlyCollection<string>> { ["province"] = provinces });

    private static Admin TehranAdmin() => new("tehran-admin", false, "orders:Sales:Order:Read");

    [Fact]
    public async Task Delegated_admin_cannot_grant_a_permission_they_do_not_hold()
    {
        var (guard, _) = Create(TehranAdmin());

        var result = await guard.EnsureCanGrantPermissionsAsync(["orders:Sales:Order:Read", "orders:Sales:Order:Approve"], Ct);

        Assert.Equal("delegation.permission_not_held", result.Error?.Code);
        Assert.Equal(ErrorKind.Forbidden, result.Error?.Kind);
    }

    [Fact]
    public async Task Super_admin_and_system_work_are_not_restricted()
    {
        var (superGuard, _) = Create(new Admin("root", true));
        var (systemGuard, _) = Create(new Admin(null, false));

        Assert.True((await superGuard.EnsureCanAssignAsync([Assign("Approver", "fars")], Ct)).IsSuccess);
        Assert.True((await systemGuard.EnsureCanManageUserAsync("shiraz-user", Ct)).IsSuccess);
    }

    [Fact]
    public async Task Assignments_stay_inside_the_admins_values()
    {
        var (guard, _) = Create(TehranAdmin());

        Assert.True((await guard.EnsureCanAssignAsync([Assign("Clerk", "tehran")], Ct)).IsSuccess);
        Assert.Equal("delegation.scope_outside_admin", (await guard.EnsureCanAssignAsync([Assign("Clerk", "fars")], Ct)).Error?.Code);
        Assert.Equal("delegation.scope_outside_admin", (await guard.EnsureCanAssignAsync([Assign("Clerk", "*")], Ct)).Error?.Code);
        Assert.Equal("delegation.scope_outside_admin", (await guard.EnsureCanAssignAsync([Assign("Clerk")], Ct)).Error?.Code);
    }

    [Fact]
    public async Task A_role_with_more_permissions_than_the_admin_cannot_be_assigned()
    {
        var (guard, _) = Create(TehranAdmin());

        var result = await guard.EnsureCanAssignAsync([Assign("Approver", "tehran")], Ct);

        Assert.Equal("delegation.role_exceeds_permissions", result.Error?.Code);
    }

    [Fact]
    public async Task Users_outside_the_admins_scope_cannot_be_managed()
    {
        var (guard, _) = Create(TehranAdmin());

        Assert.True((await guard.EnsureCanManageUserAsync("tehran-user", Ct)).IsSuccess);
        Assert.Equal("delegation.user_outside_admin", (await guard.EnsureCanManageUserAsync("shiraz-user", Ct)).Error?.Code);
        // A user without a province value sees every province, so a Tehran admin cannot manage them.
        Assert.Equal("delegation.user_outside_admin", (await guard.EnsureCanManageUserAsync("unscoped-user", Ct)).Error?.Code);
    }

    [Fact]
    public async Task User_lists_are_filtered_to_the_admins_scope()
    {
        var (guard, _) = Create(TehranAdmin());
        var (superGuard, _) = Create(new Admin("root", true));
        string[] ids = ["shiraz-user", "tehran-user", "unscoped-user"];

        Assert.Equal(["tehran-user"], (await guard.FilterManageableAsync(ids, Ct)).Value);
        Assert.Equal(ids, (await superGuard.FilterManageableAsync(ids, Ct)).Value);
        Assert.True((await guard.IsRestrictedAsync(Ct)).Value);
        Assert.False((await superGuard.IsRestrictedAsync(Ct)).Value);
    }

    [Fact]
    public async Task Orchestrator_does_not_create_a_user_outside_the_admins_scope()
    {
        var (guard, _) = Create(TehranAdmin());
        var users = new CountingUsers();
        var orchestrator = new ProvisioningOrchestrator(users, new NoScopes(), new Roles(RolePermissions), new NoMembership(), delegation: guard);

        var created = await orchestrator.CreateUserWithAssignmentsAsync(
            new CreateUserRequest("ali", null, null, null, true, null, [Assign("Clerk", "fars")]), Ct);

        Assert.Equal("delegation.scope_outside_admin", created.Error?.Code);
        Assert.Equal(0, users.Created);
    }

    private sealed class CountingUsers : IUserProvisioningService
    {
        public int Created { get; private set; }
        public Task<Result<UserDto>> GetAsync(string userId, CancellationToken ct) => throw new NotSupportedException();
        public Task<Result<UserDto>> CreateUserAsync(CreateUserRequest request, CancellationToken ct)
        {
            Created++;
            return Task.FromResult(Result<UserDto>.Success(new UserDto("u1", request.Username, null, true, new Dictionary<string, string[]>())));
        }
        public Task<Result<UserDto>> UpdateUserAsync(string userId, UpdateUserRequest request, CancellationToken ct) => throw new NotSupportedException();
        public Task<Result> DeleteUserAsync(string userId, CancellationToken ct) => throw new NotSupportedException();
        public Task<Result> ResetPasswordAsync(string userId, string newPassword, bool temporary, CancellationToken ct) => throw new NotSupportedException();
    }

    private sealed class NoScopes : IScopedAccessStore
    {
        public Task<Result<ScopedAccessDocument>> GetAsync(string userId, CancellationToken ct) =>
            Task.FromResult(Result<ScopedAccessDocument>.Success(ScopedAccessDocument.Empty));
        public Task<Result> SetAsync(string userId, ScopedAccessDocument document, CancellationToken ct) => Task.FromResult(Result.Success());
    }

    private sealed class NoMembership : IUserRoleMapping
    {
        public Task<Result> AssignRoleAsync(string userId, string roleName, CancellationToken ct) => Task.FromResult(Result.Success());
        public Task<Result> UnassignRoleAsync(string userId, string roleName, CancellationToken ct) => Task.FromResult(Result.Success());
    }
}
