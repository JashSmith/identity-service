using Identity.Application.Scope;
using Identity.Contracts;

namespace Identity.Application;

/// <summary>The administrator performing the current request.</summary>
public interface ICurrentAdministrator
{
    /// <summary>Null for system work (startup, background jobs), which is not restricted.</summary>
    string? UserId { get; }

    /// <summary>Full permission names from the administrator's token.</summary>
    IReadOnlyCollection<string> Permissions { get; }

    /// <summary>Members of super-admins are never restricted.</summary>
    Task<Result<bool>> IsSuperAdminAsync(CancellationToken ct);
}

/// <summary>
/// Delegated administration: an administrator who is not a super-admin can only
/// <list type="bullet">
/// <item>grant roles and permissions they hold themselves;</item>
/// <item>assign scope values inside their own scope (for every key they are restricted on);</item>
/// <item>manage users who are inside their own scope.</item>
/// </list>
/// A key the administrator has no value for, or holds "*" for, does not restrict them.
/// </summary>
public sealed class DelegationGuard(ICurrentAdministrator admin, IUserScopeReader scopes, IBusinessRoleStore roles)
{
    private static Error Denied(string code, string message) => Error.Forbidden(code, message);

    public async Task<Result> EnsureCanGrantPermissionsAsync(IEnumerable<string> permissions, CancellationToken ct)
    {
        var unrestricted = await IsUnrestrictedAsync(ct);
        if (!unrestricted.IsSuccess) return unrestricted.Error!;
        if (unrestricted.Value) return Result.Success();

        var missing = permissions.Where(p => !admin.Permissions.Contains(p, StringComparer.Ordinal)).ToArray();
        return missing.Length == 0
            ? Result.Success()
            : Denied("delegation.permission_not_held", $"You can only grant permissions you hold: {string.Join(", ", missing)}.");
    }

    public async Task<Result> EnsureCanAssignAsync(IEnumerable<ScopedRoleAssignmentDto> assignments, CancellationToken ct)
    {
        var unrestricted = await IsUnrestrictedAsync(ct);
        if (!unrestricted.IsSuccess) return unrestricted.Error!;
        if (unrestricted.Value) return Result.Success();

        var limits = await AdminLimitsAsync(ct);
        if (!limits.IsSuccess) return limits.Error!;

        foreach (var assignment in assignments)
        {
            var role = await roles.GetAsync(assignment.Role, ct);
            if (!role.IsSuccess) return role.Error!;
            var granted = await EnsureCanGrantPermissionsAsync(role.Value.Permissions, ct);
            if (!granted.IsSuccess)
                return Denied("delegation.role_exceeds_permissions", $"Role '{assignment.Role}' grants permissions you do not hold.");

            foreach (var (key, allowed) in limits.Value)
            {
                var values = assignment.Scopes?.GetValueOrDefault(key) ?? [];
                if (values.Count == 0 || values.Contains(ScopeAssignmentValidator.Wildcard) || values.Any(v => !allowed.Contains(v)))
                    return Denied("delegation.scope_outside_admin",
                        $"Assignments of role '{assignment.Role}' must stay within your '{key}' values: {string.Join(", ", allowed)}.");
            }
        }
        return Result.Success();
    }

    public async Task<Result> EnsureCanManageUserAsync(string userId, CancellationToken ct)
    {
        var unrestricted = await IsUnrestrictedAsync(ct);
        if (!unrestricted.IsSuccess) return unrestricted.Error!;
        if (unrestricted.Value) return Result.Success();

        var limits = await AdminLimitsAsync(ct);
        if (!limits.IsSuccess) return limits.Error!;
        var target = await scopes.GetEffectiveAsync(userId, ct);
        if (!target.IsSuccess) return target.Error!;

        var outside = FirstKeyOutside(limits.Value, target.Value);
        return outside is null
            ? Result.Success()
            : Denied("delegation.user_outside_admin", $"This user is outside your '{outside}' scope.");
    }

    /// <summary>True when the administrator is limited by delegation (not a super-admin and not system work).</summary>
    public async Task<Result<bool>> IsRestrictedAsync(CancellationToken ct)
    {
        var unrestricted = await IsUnrestrictedAsync(ct);
        return unrestricted.IsSuccess ? !unrestricted.Value : unrestricted.Error!;
    }

    /// <summary>The subset of <paramref name="userIds"/> the administrator may manage, in the given order.</summary>
    public async Task<Result<IReadOnlyCollection<string>>> FilterManageableAsync(IReadOnlyCollection<string> userIds, CancellationToken ct)
    {
        var unrestricted = await IsUnrestrictedAsync(ct);
        if (!unrestricted.IsSuccess) return unrestricted.Error!;
        if (unrestricted.Value) return Result<IReadOnlyCollection<string>>.Success(userIds);

        var limits = await AdminLimitsAsync(ct);
        if (!limits.IsSuccess) return limits.Error!;
        var manageable = new List<string>();
        foreach (var id in userIds)
        {
            var target = await scopes.GetEffectiveAsync(id, ct);
            if (!target.IsSuccess) return target.Error!;
            if (FirstKeyOutside(limits.Value, target.Value) is null) manageable.Add(id);
        }
        return manageable;
    }

    /// <summary>
    /// The first key on which the user is outside the limits. A user without values for a key (or with "*")
    /// is not restricted on it, so it is outside a restricted administrator's scope.
    /// </summary>
    private static string? FirstKeyOutside(IReadOnlyDictionary<string, HashSet<string>> limits,
        IReadOnlyDictionary<string, IReadOnlyCollection<string>> target)
    {
        foreach (var (key, allowed) in limits)
        {
            var values = target.GetValueOrDefault(key) ?? [];
            if (values.Count == 0 || values.Contains(ScopeAssignmentValidator.Wildcard) || values.Any(v => !allowed.Contains(v)))
                return key;
        }
        return null;
    }

    private async Task<Result<bool>> IsUnrestrictedAsync(CancellationToken ct) =>
        admin.UserId is null ? true : await admin.IsSuperAdminAsync(ct);

    /// <summary>The keys the administrator is restricted on, with their allowed values.</summary>
    private async Task<Result<IReadOnlyDictionary<string, HashSet<string>>>> AdminLimitsAsync(CancellationToken ct)
    {
        var effective = await scopes.GetEffectiveAsync(admin.UserId!, ct);
        if (!effective.IsSuccess) return effective.Error!;
        return effective.Value
            .Where(kv => kv.Value.Count > 0 && !kv.Value.Contains(ScopeAssignmentValidator.Wildcard))
            .ToDictionary(kv => kv.Key, kv => kv.Value.ToHashSet(StringComparer.Ordinal), StringComparer.Ordinal);
    }
}
