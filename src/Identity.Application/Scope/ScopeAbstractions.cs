using Identity.Contracts;

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

/// <summary>
/// Scope definitions from the registry. Failures (registry unreachable) are errors: validation must fail
/// closed instead of accepting scopes it could not check.
/// </summary>
public interface IScopeDefinitionLookup
{
    Task<Result<bool>> ExistsActiveAsync(string key, CancellationToken ct);

    /// <summary>True when the role restricts nothing (no authz.allowed-scopes) or lists the scope.</summary>
    Task<Result<bool>> IsScopeAllowedForRoleAsync(string role, string scopeKey, CancellationToken ct);

    /// <summary>Parent key and value catalog of an active scope; scope.not_found otherwise.</summary>
    Task<Result<ScopeRules>> GetRulesAsync(string key, CancellationToken ct);
}

public sealed record ScopeDefinitionDto(string Key, string DisplayName, string? Description, bool IsActive, string ValueType,
    string? Parent = null);

/// <summary>What validation needs to know about one scope key.</summary>
public sealed record ScopeRules(string Key, string? Parent, IReadOnlyCollection<ScopeValueDto> Values);

public sealed record ResourceScopeMappingDto(string Key, IReadOnlyCollection<string> Scopes);

/// <summary>
/// Administration of the scope registry (the iam-scope-registry group). Errors: scope.not_found,
/// scope.already_exists, or a Keycloak availability error. Creating a scope also declares its user
/// attribute and token claim; when that fails the scope is removed again.
/// </summary>
public interface IScopeRegistryAdmin
{
    Task<Result<IReadOnlyCollection<ScopeDefinitionDto>>> ListScopesAsync(CancellationToken ct);
    Task<Result<ScopeDefinitionDto>> GetScopeAsync(string key, CancellationToken ct);
    Task<Result<IReadOnlyCollection<ResourceScopeMappingDto>>> ListResourcesAsync(CancellationToken ct);
    Task<Result<IReadOnlyCollection<string>>> GetResourcesForScopeAsync(string key, CancellationToken ct);
    Task<Result<ScopeDefinitionDto>> CreateScopeAsync(string key, string? displayName, string? description,
        IReadOnlyCollection<string>? resources, string? parent, CancellationToken ct);
    Task<Result<ScopeDefinitionDto>> UpdateScopeAsync(string key, string? displayName, string? description, bool? isActive,
        IReadOnlyCollection<string>? resources, string? parent, CancellationToken ct);
    Task<Result<IReadOnlyCollection<ScopeValueDto>>> GetValuesAsync(string key, CancellationToken ct);
    Task<Result> SetValuesAsync(string key, IReadOnlyCollection<ScopeValueDto> values, CancellationToken ct);
    Task<Result> DeleteScopeAsync(string key, CancellationToken ct);
    Task<Result> SetScopeResourcesAsync(string key, IReadOnlyCollection<string> resources, CancellationToken ct);
}

public interface IScopeCacheInvalidator { void Invalidate(); }
