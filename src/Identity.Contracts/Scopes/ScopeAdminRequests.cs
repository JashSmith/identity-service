namespace Identity.Contracts;

/// <summary>Defines a new runtime scope in the registry, optionally mapped to the resources it filters.</summary>
/// <param name="Parent">Key of the enclosing scope (e.g. "province" for "city"); its values bound this scope's values.</param>
public sealed record CreateScopeRequest(
    string Key,
    string? DisplayName,
    string? Description,
    IReadOnlyCollection<string>? TargetResources = null,
    string? Parent = null);

/// <summary>Changes the given fields of a scope; null keeps the current value.</summary>
public sealed record UpdateScopeRequest(
    string? DisplayName,
    string? Description,
    bool? IsActive,
    IReadOnlyCollection<string>? TargetResources = null,
    string? Parent = null);

/// <summary>
/// One allowed value of a scope, e.g. ("tehran-2", "تهران - منطقه ۲", parent "tehran"). When a scope has values,
/// assignments may only use those values (or "*" where the role allows it).
/// </summary>
public sealed record ScopeValueDto(string Value, string? Label, string? Parent = null);

/// <summary>Replaces the value catalog of a scope; an empty list allows free-text values again.</summary>
public sealed record SetScopeValuesRequest(IReadOnlyCollection<ScopeValueDto> Values);

/// <summary>Replaces the resources a scope filters.</summary>
public sealed record SetScopeResourcesRequest(IReadOnlyCollection<string> Resources);
