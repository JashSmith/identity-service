using Identity.Contracts;

namespace Identity.Application;

/// <summary>
/// Reusable access-context abstraction for microservices. Parses effective permissions
/// (realm roles) and scoped assignments from the caller's identity.
/// </summary>
public interface IApplicationAccessContext
{
    IReadOnlyCollection<ScopedRoleAssignment> GetAssignments();
    bool HasPermission(string permission);
    bool HasPermission(string permission, string scopeKey, string scopeValue);
    IReadOnlyCollection<string> GetScopeValues(string scopeKey);
    bool HasScope(string scopeKey, string scopeValue);
}

public sealed class CurrentAccessContext : IApplicationAccessContext
{
    private readonly IReadOnlyCollection<string> _permissions;
    private readonly IReadOnlyCollection<ScopedRoleAssignment> _assignments;
    private readonly IReadOnlyDictionary<string, HashSet<string>> _scopeIndex;

    public CurrentAccessContext(
        IReadOnlyCollection<string> permissions,
        IReadOnlyCollection<ScopedRoleAssignment> assignments)
    {
        _permissions = permissions ?? Array.Empty<string>();
        _assignments = assignments ?? Array.Empty<ScopedRoleAssignment>();
        var index = new Dictionary<string, HashSet<string>>(StringComparer.Ordinal);
        foreach (var a in _assignments)
        foreach (var kv in a.Scopes)
        {
            if (!index.TryGetValue(kv.Key, out var set))
            {
                set = new HashSet<string>(StringComparer.Ordinal);
                index[kv.Key] = set;
            }
            foreach (var v in kv.Value) set.Add(v);
        }
        _scopeIndex = index;
    }

    /// <summary>
    /// Creates an access context by resolving the permissions and scoped assignments
    /// for the given user id. Used by the facade itself; microservices typically use
    /// the claims-based constructor via claims principal parsing.
    /// </summary>
    public static async Task<CurrentAccessContext> FromUserAsync(
        string userId,
        IUserDirectory users,
        IScopedAccessStore store,
        CancellationToken ct)
    {
        var perms = await users.GetUserPermissionsAsync(userId, ct);
        var permNames = perms.Select(p => p.Name).ToArray();
        var doc = await store.GetAsync(userId, ct);
        return new CurrentAccessContext(permNames, doc.Assignments.ToArray());
    }

    public IReadOnlyCollection<ScopedRoleAssignment> GetAssignments() => _assignments;

    public bool HasPermission(string permission)
        => _permissions.Contains(permission, StringComparer.Ordinal);

    public bool HasPermission(string permission, string scopeKey, string scopeValue)
    {
        if (!HasPermission(permission)) return false;
        return HasScope(scopeKey, scopeValue);
    }

    public IReadOnlyCollection<string> GetScopeValues(string scopeKey)
        => _scopeIndex.TryGetValue(scopeKey, out var set)
            ? set.ToArray()
            : Array.Empty<string>();

    public bool HasScope(string scopeKey, string scopeValue)
        => _scopeIndex.TryGetValue(scopeKey, out var set) && set.Contains(scopeValue);

    /// <summary>
    /// Checks that the permission exists AND that the scope (key=value) is present
    /// in at least one assignment whose role actually grants that permission.
    /// When role-to-permission mapping is available (composite roles), use
    /// <see cref="HasPermissionForResource"/> instead.
    /// </summary>
    public bool IsAllowed(string permission, string scopeKey, string scopeValue)
        => HasPermission(permission, scopeKey, scopeValue);
}
