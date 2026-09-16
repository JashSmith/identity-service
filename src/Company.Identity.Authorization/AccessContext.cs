using System.Security.Claims;
using Identity.Contracts;

namespace Company.Identity.Authorization;

/// <summary>
/// Reusable access-context abstraction for microservices. Provides EF-Core-friendly primitives.
/// Centralizes parsing of the compact <c>iam_access</c> claim so business code never touches raw claim values.
/// </summary>
public interface ICurrentAccessContext
{
    IReadOnlyCollection<ScopedRoleAssignment> GetAssignments();
    bool HasPermission(string permission);
    bool HasPermission(string permission, string scopeKey, string scopeValue);
    IReadOnlyCollection<string> GetScopeValues(string scopeKey);
    bool HasScope(string scopeKey, string scopeValue);
}

public sealed class ClaimsPrincipalAccessContext : ICurrentAccessContext
{
    private readonly IReadOnlyCollection<string> _permissions;
    private readonly IReadOnlyCollection<ScopedRoleAssignment> _assignments;
    private readonly IReadOnlyDictionary<string, HashSet<string>> _scopeIndex;

    public ClaimsPrincipalAccessContext(ClaimsPrincipal principal)
    {
        _permissions = principal.FindAll("permission")
            .Concat(principal.FindAll("permissions"))
            .Select(c => c.Value)
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        // Also include role claims as permissions for compatibility
        var roles = principal.FindAll(ClaimTypes.Role).Concat(principal.FindAll("role")).Select(c => c.Value);
        _permissions = _permissions.Concat(roles).Distinct(StringComparer.Ordinal).ToArray();

        _assignments = ParseAssignments(principal);

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

    private static IReadOnlyCollection<ScopedRoleAssignment> ParseAssignments(ClaimsPrincipal principal)
    {
        var claimValues = principal.FindAll(ScopedAccessConstants.ClaimName).Select(c => c.Value).ToArray();
        if (claimValues.Length == 0) return Array.Empty<ScopedRoleAssignment>();

        // The claim may be a single JSON array string or multiple string claims.
        // Try single-value JSON array first.
        var combined = claimValues.Length == 1 ? claimValues[0] : string.Join("", claimValues);
        if (string.IsNullOrWhiteSpace(combined)) return Array.Empty<ScopedRoleAssignment>();

        try
        {
            var doc = System.Text.Json.JsonDocument.Parse(combined);
            if (doc.RootElement.ValueKind == System.Text.Json.JsonValueKind.Array)
            {
                return System.Text.Json.JsonSerializer.Deserialize<ScopedRoleAssignment[]>(
                    combined,
                    new System.Text.Json.JsonSerializerOptions { PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase })
                    ?.Where(a => !string.IsNullOrWhiteSpace(a.Role))
                    .Select(a => new ScopedRoleAssignment(
                        a.Role.Trim(),
                        NormalizeScopes(a.Scopes)))
                    .ToArray() ?? Array.Empty<ScopedRoleAssignment>();
            }
        }
        catch { }

        return Array.Empty<ScopedRoleAssignment>();
    }

    private static IReadOnlyDictionary<string, IReadOnlyCollection<string>> NormalizeScopes(
        IReadOnlyDictionary<string, IReadOnlyCollection<string>>? scopes)
    {
        if (scopes is null || scopes.Count == 0)
            return new Dictionary<string, IReadOnlyCollection<string>>(StringComparer.Ordinal);
        var result = new Dictionary<string, IReadOnlyCollection<string>>(StringComparer.Ordinal);
        foreach (var kv in scopes)
        {
            var key = kv.Key?.Trim();
            if (string.IsNullOrWhiteSpace(key)) continue;
            var values = kv.Value?.Where(v => !string.IsNullOrWhiteSpace(v))
                .Select(v => v.Trim())
                .Distinct(StringComparer.Ordinal)
                .ToArray() ?? Array.Empty<string>();
            if (values.Length == 0) continue;
            result[key!] = values;
        }
        return result;
    }
}
