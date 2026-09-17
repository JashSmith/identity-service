using Identity.Contracts;

namespace Company.Identity.Authorization;

public interface IResourceAccessContext : ICurrentAccessContext
{
    bool CanUseScope(string scopeKey, string resourceKey);
}

public sealed class ResourceAwareAccessContext : IResourceAccessContext
{
    private readonly ICurrentAccessContext _inner;
    private readonly IReadOnlyDictionary<string, HashSet<string>> _resourceMap;

    public ResourceAwareAccessContext(ICurrentAccessContext inner, IReadOnlyDictionary<string, HashSet<string>> resourceMap)
    {
        _inner = inner;
        _resourceMap = resourceMap;
    }

    public IReadOnlyCollection<ScopedRoleAssignment> GetAssignments() => _inner.GetAssignments();
    public bool HasPermission(string p) => _inner.HasPermission(p);
    public bool HasPermission(string p, string k, string v) => _inner.HasPermission(p, k, v);
    public IReadOnlyCollection<string> GetScopeValues(string k) => _inner.GetScopeValues(k);
    public bool HasScope(string k, string v) => _inner.HasScope(k, v);
    public Task EnsureLoadedAsync(CancellationToken ct = default) => _inner.EnsureLoadedAsync(ct);

    public bool CanUseScope(string scopeKey, string resourceKey)
        => _resourceMap.TryGetValue(resourceKey, out var allowed) && allowed.Contains(scopeKey);
}
