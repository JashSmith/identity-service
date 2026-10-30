using Identity.Contracts;

namespace Identity.Application.Scope;

/// <summary>
/// The scopes a user effectively holds, as tokens see them: the user's own authz.scope.* values merged
/// with those of every group the user belongs to. Read-only; writes go through <see cref="IScopedAccessStore"/>.
/// </summary>
public interface IUserScopeReader
{
    /// <summary>The merged view, one entry per group (or "_user" when the user has no group).</summary>
    Task<Result<ScopedAccessDocument>> GetAsync(string userId, CancellationToken ct);

    /// <summary>The merged values per scope key.</summary>
    Task<Result<IReadOnlyDictionary<string, IReadOnlyCollection<string>>>> GetEffectiveAsync(string userId, CancellationToken ct);
}

public interface IResourceScopeResolver
{
    Task<HashSet<string>> GetScopesForResourceAsync(string resourceKey, CancellationToken ct);
}
