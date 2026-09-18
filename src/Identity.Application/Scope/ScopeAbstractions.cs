namespace Identity.Application.Scope;

public interface IScopeValueValidator
{
    string ScopeKey { get; }
    bool IsValid(string value, out string? error);
}

public sealed class DefaultScopeValueValidator : IScopeValueValidator
{
    public string ScopeKey => "*";
    public bool IsValid(string value, out string? error)
    {
        if (string.IsNullOrWhiteSpace(value)) { error = "Scope value must not be empty."; return false; }
        if (value.Length > 256) { error = "Scope value exceeds 256 characters."; return false; }
        error = null; return true;
    }
}

public interface IScopeValueValidatorRegistry
{
    IScopeValueValidator GetValidator(string scopeKey);
}

public sealed class ScopeValueValidatorRegistry(IEnumerable<IScopeValueValidator> validators) : IScopeValueValidatorRegistry
{
    private readonly Dictionary<string, IScopeValueValidator> _map = validators
        .GroupBy(v => v.ScopeKey, StringComparer.OrdinalIgnoreCase)
        .ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);
    public IScopeValueValidator GetValidator(string scopeKey)
        => _map.TryGetValue(scopeKey, out var v) ? v : _map.TryGetValue("*", out var d) ? d : new DefaultScopeValueValidator();
}

public interface IScopeDefinitionLookup
{
    Task<bool> ExistsActiveAsync(string key, CancellationToken ct);
    Task<bool> IsScopeAllowedForRoleAsync(string role, string scopeKey, CancellationToken ct);
}

public sealed record ScopeDefinitionDto(string Key, string DisplayName, string? Description, bool IsActive, string ValueType);

public sealed record ResourceScopeMappingDto(string Key, IReadOnlyCollection<string> Scopes);

/// <summary>
/// Admin-side CRUD for the scope registry (scope definitions + resource mappings).
/// Backed by the Keycloak <c>iam-scope-registry</c> group attributes.
/// </summary>
public interface IScopeRegistryAdmin
{
    Task<IReadOnlyCollection<ScopeDefinitionDto>> ListScopesAsync(CancellationToken ct);
    Task<ScopeDefinitionDto?> GetScopeAsync(string key, CancellationToken ct);
    Task<IReadOnlyCollection<ResourceScopeMappingDto>> ListResourcesAsync(CancellationToken ct);
    Task<ScopeDefinitionDto?> CreateScopeAsync(string key, string? displayName, string? description, CancellationToken ct);
    Task<ScopeDefinitionDto?> UpdateScopeAsync(string key, string? displayName, string? description, bool? isActive, CancellationToken ct);
}

public interface IScopeCacheInvalidator { void Invalidate(); }
