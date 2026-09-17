using Identity.Contracts;

namespace Identity.Application.Scope;

public interface IUserScopeReader
{
    Task<ScopedAccessDocument> GetAsync(string userId, CancellationToken ct);
    Task<IReadOnlyDictionary<string, IReadOnlyCollection<string>>> GetEffectiveAsync(string userId, CancellationToken ct);
}
public interface IUserScopeWriter
{
    Task SetAsync(string userId, IReadOnlyCollection<ScopedRoleAssignmentDto> assignments, CancellationToken ct);
}

public interface IResourceScopeResolver
{
    Task<HashSet<string>> GetScopesForResourceAsync(string resourceKey, CancellationToken ct);
}
