using Identity.Application.Scope;
using Identity.Contracts;

namespace Identity.Application;

/// <summary>
/// Creates users with their business roles and runtime scopes, and changes those assignments, keeping
/// scope attributes and role membership consistent: when a later step fails, the earlier steps are
/// undone instead of leaving a user with half of the access that was asked for.
/// </summary>
public sealed class ProvisioningOrchestrator(
    IUserProvisioningService users,
    IScopedAccessStore scopedStore,
    IBusinessRoleStore roles,
    IUserRoleMapping roleMapping,
    ScopeAssignmentValidator? scopeValidator = null,
    IUserProfileRequirements? profileRequirements = null,
    DelegationGuard? delegation = null,
    IScopeDefinitionLookup? scopeLookup = null)
{
    public async Task<Result<(UserDto User, ScopedAccessDocument Scoped)>> CreateUserWithAssignmentsAsync(
        CreateUserRequest request, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(request);
        var assignments = request.Assignments ?? [];
        var invalid = await ValidateProfileAsync(request, ct) ?? await ValidateAssignmentsAsync(assignments, ct);
        if (invalid is not null) return invalid;
        var delegated = await CheckDelegationAsync(null, assignments, ct);
        if (!delegated.IsSuccess) return delegated.Error!;

        var created = await users.CreateUserAsync(request, ct);
        if (!created.IsSuccess) return created.Error!;
        if (assignments.Count == 0) return (created.Value, ScopedAccessDocument.Empty);

        var document = ToDocument(assignments);
        var applied = await ApplyAsync(created.Value.Id, ScopedAccessDocument.Empty, document, ct);
        if (applied.IsSuccess) return (created.Value, document);

        // A user without the access the admin asked for must not stay behind.
        var removed = await users.DeleteUserAsync(created.Value.Id, ct);
        return removed.IsSuccess
            ? applied.Error!
            : applied.Error! with { Message = $"{applied.Error!.Message} The new user '{request.Username}' could not be removed again ({removed.Error!.Code})." };
    }

    public async Task<Result<ScopedAccessDocument>> AddScopedAssignmentAsync(
        string userId, ScopedRoleAssignmentDto assignment, CancellationToken ct)
    {
        var user = await users.GetAsync(userId, ct);
        if (!user.IsSuccess) return user.Error!;
        var invalid = await ValidateAssignmentsAsync([assignment], ct);
        if (invalid is not null) return invalid;
        var delegated = await CheckDelegationAsync(userId, [assignment], ct);
        if (!delegated.IsSuccess) return delegated.Error!;

        var current = await ReadScopesAsync(userId, ct);
        if (!current.IsSuccess) return current.Error!;
        var others = current.Value.Assignments
            .Where(a => !string.Equals(a.Role, assignment.Role.Trim(), StringComparison.Ordinal));
        var next = new ScopedAccessDocument(others.Concat(ToDocument([assignment]).Assignments)
            .OrderBy(a => a.Role, StringComparer.Ordinal).ToArray());

        var applied = await ApplyAsync(userId, current.Value, next, ct);
        return applied.IsSuccess ? await ReadScopesAsync(userId, ct) : applied.Error!;
    }

    public async Task<Result<ScopedAccessDocument>> ReplaceAssignmentsAsync(
        string userId, IReadOnlyCollection<ScopedRoleAssignmentDto> assignments, CancellationToken ct)
    {
        var user = await users.GetAsync(userId, ct);
        if (!user.IsSuccess) return user.Error!;
        var invalid = await ValidateAssignmentsAsync(assignments, ct);
        if (invalid is not null) return invalid;
        var delegated = await CheckDelegationAsync(userId, assignments, ct);
        if (!delegated.IsSuccess) return delegated.Error!;

        var current = await ReadScopesAsync(userId, ct);
        if (!current.IsSuccess) return current.Error!;
        var next = ToDocument(assignments);

        var applied = await ApplyAsync(userId, current.Value, next, ct);
        return applied.IsSuccess ? next : applied.Error!;
    }

    public async Task<Result<ScopedAccessDocument>> UpdateScopedAssignmentAsync(
        string userId, string role, IReadOnlyDictionary<string, IReadOnlyCollection<string>> scopes, CancellationToken ct)
    {
        var user = await users.GetAsync(userId, ct);
        if (!user.IsSuccess) return user.Error!;
        var invalid = await ValidateAssignmentsAsync([new ScopedRoleAssignmentDto(role, scopes)], ct);
        if (invalid is not null) return invalid;
        var delegated = await CheckDelegationAsync(userId, [new ScopedRoleAssignmentDto(role, scopes)], ct);
        if (!delegated.IsSuccess) return delegated.Error!;

        var current = await ReadScopesAsync(userId, ct);
        if (!current.IsSuccess) return current.Error!;
        if (!current.Value.Assignments.Any(a => string.Equals(a.Role, role.Trim(), StringComparison.Ordinal)))
            return Error.NotFound("assignment.not_found", $"User '{userId}' has no assignment for role '{role}'.");

        var next = new ScopedAccessDocument(current.Value.Assignments
            .Select(a => string.Equals(a.Role, role.Trim(), StringComparison.Ordinal)
                ? ToDocument([new ScopedRoleAssignmentDto(a.Role, scopes)]).Assignments.Single()
                : a)
            .ToArray());
        var applied = await ApplyAsync(userId, current.Value, next, ct);
        return applied.IsSuccess ? next : applied.Error!;
    }

    public async Task<Result> RemoveScopedAssignmentAsync(string userId, string role, CancellationToken ct)
    {
        var user = await users.GetAsync(userId, ct);
        if (!user.IsSuccess) return user.Error!;
        var delegated = await CheckDelegationAsync(userId, [], ct);
        if (!delegated.IsSuccess) return delegated;

        var current = await ReadScopesAsync(userId, ct);
        if (!current.IsSuccess) return current.Error!;
        var next = new ScopedAccessDocument(current.Value.Assignments
            .Where(a => !string.Equals(a.Role, role, StringComparison.Ordinal)).ToArray());

        var applied = await ApplyAsync(userId, current.Value, next, ct);
        return applied.IsSuccess ? Result.Success() : applied.Error!;
    }

    /// <summary>Deletes the role; the store refuses while users still hold it (role.in_use).</summary>
    public Task<Result> DeleteBusinessRoleSafeAsync(string roleName, CancellationToken ct) =>
        roles.DeleteAsync(roleName, ct);

    /// <summary>Creates a role; delegated admins may only grant permissions they hold, policy keys must be registry scopes.</summary>
    public async Task<Result<BusinessRoleDto>> CreateBusinessRoleAsync(string name, string? description,
        IReadOnlyCollection<string> permissions, RoleScopePolicy? policy, CancellationToken ct)
    {
        var granted = delegation is null ? Result.Success() : await delegation.EnsureCanGrantPermissionsAsync(permissions, ct);
        if (!granted.IsSuccess) return granted.Error!;
        var validPolicy = await ValidatePolicyAsync(policy, ct);
        if (!validPolicy.IsSuccess) return validPolicy.Error!;
        // Permission existence is checked by the role store against Keycloak (source of truth).
        return await roles.CreateAsync(name.Trim(), description, permissions ?? [], policy, ct);
    }

    /// <summary>Changes the description, the exact permission set and/or the scope policy of a role.</summary>
    public async Task<Result<BusinessRoleDto>> UpdateBusinessRoleAsync(string name, UpdateBusinessRoleRequest request, CancellationToken ct)
    {
        var updated = await roles.UpdateAsync(name, request.Description, ct);
        if (!updated.IsSuccess) return updated;

        if (request.Permissions is not null)
        {
            var added = request.Permissions.Except(updated.Value.Permissions, StringComparer.Ordinal).ToArray();
            var granted = delegation is null ? Result.Success() : await delegation.EnsureCanGrantPermissionsAsync(added, ct);
            if (!granted.IsSuccess) return granted.Error!;
            var set = await roles.SetPermissionsAsync(name, request.Permissions, ct);
            if (!set.IsSuccess) return set.Error!;
        }

        if (request.RequiredScopes is not null || request.AllowedScopes is not null)
        {
            var policy = new RoleScopePolicy(request.RequiredScopes ?? updated.Value.RequiredScopes ?? [],
                request.AllowedScopes ?? updated.Value.AllowedScopes ?? []);
            var validPolicy = await ValidatePolicyAsync(policy, ct);
            if (!validPolicy.IsSuccess) return validPolicy.Error!;
            var set = await roles.SetScopePolicyAsync(name, policy, ct);
            if (!set.IsSuccess) return set.Error!;
        }
        return await roles.GetAsync(name, ct);
    }

    public async Task<Result> AddRolePermissionsAsync(string name, IReadOnlyCollection<string> permissions, CancellationToken ct)
    {
        var granted = delegation is null ? Result.Success() : await delegation.EnsureCanGrantPermissionsAsync(permissions, ct);
        return granted.IsSuccess ? await roles.AddPermissionsAsync(name, permissions, ct) : granted;
    }

    /// <summary>Delegated admins may only change users and assignments inside their own scope.</summary>
    public Task<Result> EnsureCanManageUserAsync(string userId, CancellationToken ct) =>
        delegation is null ? Task.FromResult(Result.Success()) : delegation.EnsureCanManageUserAsync(userId, ct);

    private async Task<Result> CheckDelegationAsync(string? targetUserId, IReadOnlyCollection<ScopedRoleAssignmentDto> assignments, CancellationToken ct)
    {
        if (delegation is null) return Result.Success();
        if (targetUserId is not null)
        {
            var managed = await delegation.EnsureCanManageUserAsync(targetUserId, ct);
            if (!managed.IsSuccess) return managed;
        }
        return assignments.Count == 0 ? Result.Success() : await delegation.EnsureCanAssignAsync(assignments, ct);
    }

    private async Task<Result> ValidatePolicyAsync(RoleScopePolicy? policy, CancellationToken ct)
    {
        if (policy is null || scopeLookup is null) return Result.Success();
        var unknown = new List<string>();
        foreach (var key in policy.Required.Concat(policy.Allowed).Distinct(StringComparer.Ordinal))
        {
            var rules = await scopeLookup.GetRulesAsync(key, ct);
            if (rules.IsSuccess) continue;
            if (rules.Error!.Kind != ErrorKind.NotFound) return rules.Error;
            unknown.Add(key);
        }
        return unknown.Count == 0
            ? Result.Success()
            : Error.Validation("scope.not_found", $"Unknown scope keys: {string.Join(", ", unknown)}.");
    }

    /// <summary>
    /// Moves a user from <paramref name="current"/> to <paramref name="next"/>: writes the scope attributes,
    /// then adds and removes role memberships. On the first failure every completed step is reverted.
    /// </summary>
    private async Task<Result> ApplyAsync(string userId, ScopedAccessDocument current, ScopedAccessDocument next, CancellationToken ct)
    {
        var currentRoles = current.Assignments.Select(a => a.Role).ToHashSet(StringComparer.Ordinal);
        var nextRoles = next.Assignments.Select(a => a.Role).ToHashSet(StringComparer.Ordinal);

        var written = await scopedStore.SetAsync(userId, next, ct);
        if (!written.IsSuccess) return written;

        var done = new List<(string Role, bool Added)>();
        var changes = nextRoles.Except(currentRoles).Select(r => (Role: r, Add: true))
            .Concat(currentRoles.Except(nextRoles).Select(r => (Role: r, Add: false)));
        foreach (var (role, add) in changes)
        {
            var changed = add
                ? await roleMapping.AssignRoleAsync(userId, role, ct)
                : await roleMapping.UnassignRoleAsync(userId, role, ct);
            if (changed.IsSuccess)
            {
                done.Add((role, add));
                continue;
            }

            var undone = await UndoAsync(userId, current, done, ct);
            return undone
                ? changed
                : changed.Error! with { Message = $"{changed.Error!.Message} Earlier changes could not all be reverted; check the user's roles and scopes." };
        }
        return Result.Success();
    }

    private async Task<bool> UndoAsync(string userId, ScopedAccessDocument previous, List<(string Role, bool Added)> done, CancellationToken ct)
    {
        var ok = true;
        for (var i = done.Count - 1; i >= 0; i--)
        {
            var (role, added) = done[i];
            var reverted = added
                ? await roleMapping.UnassignRoleAsync(userId, role, ct)
                : await roleMapping.AssignRoleAsync(userId, role, ct);
            ok &= reverted.IsSuccess;
        }
        ok &= (await scopedStore.SetAsync(userId, previous, ct)).IsSuccess;
        return ok;
    }

    /// <summary>The user's own assignments; never the merged view that includes group scopes.</summary>
    private Task<Result<ScopedAccessDocument>> ReadScopesAsync(string userId, CancellationToken ct) =>
        scopedStore.GetAsync(userId, ct);

    private async Task<Error?> ValidateAssignmentsAsync(IReadOnlyCollection<ScopedRoleAssignmentDto> assignments, CancellationToken ct)
    {
        try
        {
            foreach (var a in assignments) ScopedAccessSerializer.Validate(a);
        }
        catch (ArgumentException ex)
        {
            return Error.Validation("scope.invalid", ex.Message);
        }

        if (scopeValidator is not null)
        {
            var errors = await scopeValidator.ValidateAsync(assignments, roles, ct);
            if (!errors.IsSuccess) return errors.Error;
            return errors.Value.Count == 0 ? null : Error.Validation("scope.invalid", "One or more assignments are invalid.", errors.Value);
        }

        foreach (var a in assignments)
            if (!await roles.ExistsAsync(a.Role, ct))
                return Error.Validation("role.not_found", $"Role '{a.Role}' does not exist.");
        return null;
    }

    /// <summary>Attributes the identity provider's user profile requires and the request does not carry.</summary>
    private async Task<Error?> ValidateProfileAsync(CreateUserRequest request, CancellationToken ct)
    {
        if (profileRequirements is null) return null;
        var required = await profileRequirements.GetRequiredAttributesAsync(ct);
        if (!required.IsSuccess) return required.Error;
        var missing = required.Value.Where(attr => string.IsNullOrWhiteSpace(RequestValue(request, attr))).ToArray();
        if (missing.Length == 0) return null;

        return Error.Validation("user.profile_incomplete", "The identity provider requires more profile fields.",
            missing.ToDictionary(attr => attr,
                attr => new[] { $"'{attr}' is required by the identity provider's user profile; without it the user cannot sign in." }));
    }

    /// <summary>Maps a Keycloak profile attribute name to the value carried by <see cref="CreateUserRequest"/>.</summary>
    private static string? RequestValue(CreateUserRequest r, string attribute) => attribute switch
    {
        "username" => r.Username,
        "email" => r.Email,
        "firstName" => r.FirstName,
        "lastName" => r.LastName,
        _ => null, // unknown attribute — not something the gateway can supply or judge
    };

    private static ScopedAccessDocument ToDocument(IReadOnlyCollection<ScopedRoleAssignmentDto> dtos)
    {
        var normalized = dtos.Select(dto =>
        {
            var role = dto.Role.Trim();
            var scopes = dto.Scopes is null ? new Dictionary<string, IReadOnlyCollection<string>>(StringComparer.Ordinal)
                : dto.Scopes.Where(kv => !string.IsNullOrWhiteSpace(kv.Key))
                    .ToDictionary(kv => kv.Key.Trim(), kv => kv.Value?.Where(v => !string.IsNullOrWhiteSpace(v)).Select(v => v.Trim()).Distinct(StringComparer.Ordinal).OrderBy(v => v, StringComparer.Ordinal).ToArray() as IReadOnlyCollection<string> ?? Array.Empty<string>(), StringComparer.Ordinal);
            return new ScopedRoleAssignment(role, scopes);
        }).OrderBy(a => a.Role, StringComparer.Ordinal).ToArray();
        return new ScopedAccessDocument(normalized);
    }
}
