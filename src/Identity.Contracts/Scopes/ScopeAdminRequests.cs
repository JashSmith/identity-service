namespace Identity.Contracts;

/// <summary>Defines a new runtime scope in the registry, optionally mapped to the resources it filters.</summary>
public sealed record CreateScopeRequest(
    string Key,
    string? DisplayName,
    string? Description,
    IReadOnlyCollection<string>? TargetResources = null);

/// <summary>Changes the given fields of a scope; null keeps the current value.</summary>
public sealed record UpdateScopeRequest(
    string? DisplayName,
    string? Description,
    bool? IsActive,
    IReadOnlyCollection<string>? TargetResources = null);

/// <summary>Replaces the resources a scope filters.</summary>
public sealed record SetScopeResourcesRequest(IReadOnlyCollection<string> Resources);
