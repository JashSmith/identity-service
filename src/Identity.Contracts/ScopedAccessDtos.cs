namespace Identity.Contracts;

/// <summary>
/// Central constants for the namespaced scoped-access attribute and claim.
/// Attribute is the Keycloak user-attribute key; claim is the JWT claim consumers read.
/// </summary>
public static class ScopedAccessConstants
{
    public const string AttributeName = "iam.scoped_access";
    public const string ClaimName = "iam_access";
    public const int MaxInlineClaimBytes = 4096;
}

/// <summary>
/// A single role bound to arbitrary scope dimensions. Scope keys are dynamic (region, branch, …)
/// and require no schema change to introduce a new key.
/// </summary>
public sealed record ScopedRoleAssignment(
    string Role,
    IReadOnlyDictionary<string, IReadOnlyCollection<string>> Scopes);

/// <summary>
/// The full set of scoped assignments for a user. Serialized as a JSON array of
/// <see cref="ScopedRoleAssignment"/> and stored in the single Keycloak attribute
/// <see cref="ScopedAccessConstants.AttributeName"/>.
/// </summary>
public sealed record ScopedAccessDocument(
    IReadOnlyCollection<ScopedRoleAssignment> Assignments)
{
    public static ScopedAccessDocument Empty { get; } = new(Array.Empty<ScopedRoleAssignment>());
}

// ── User management DTOs ────────────────────────────────────────────────────

public sealed record CreateUserRequest(
    string Username,
    string? Email,
    string? FirstName,
    string? LastName,
    bool Enabled,
    CredentialRequest? Credentials,
    IReadOnlyCollection<ScopedRoleAssignmentDto>? Assignments);

public sealed record UpdateUserRequest(
    string? Email,
    string? FirstName,
    string? LastName,
    bool? Enabled);

public sealed record CredentialRequest(
    string Password,
    bool Temporary);

public sealed record ScopedRoleAssignmentDto(
    string Role,
    [property: System.Text.Json.Serialization.JsonConverter(typeof(ScopeDictionaryConverter))]
    IReadOnlyDictionary<string, IReadOnlyCollection<string>> Scopes);

// ── Scoped-access management DTOs ──────────────────────────────────────────

public sealed record SetScopedAccessRequest(
    IReadOnlyCollection<ScopedRoleAssignmentDto> Assignments);

public sealed record ScopedAccessResponse(
    string UserId,
    IReadOnlyCollection<ScopedRoleAssignment> Assignments);

// ── Business role DTOs ──────────────────────────────────────────────────────

public sealed record BusinessRoleDto(
    string Name,
    string? Description,
    bool Composite,
    IReadOnlyCollection<string> Permissions);

public sealed record CreateBusinessRoleRequest(
    string Name,
    string? Description,
    IReadOnlyCollection<string>? Permissions);

public sealed record UpdateBusinessRoleRequest(
    string? Description);

public sealed record AssignPermissionsRequest(
    IReadOnlyCollection<string> Permissions);

public sealed record EffectivePermissionsResponse(
    string Role,
    IReadOnlyCollection<string> Permissions);

public sealed record AccessContextResponse(
    string? UserId,
    string? Username,
    IReadOnlyCollection<string> Permissions,
    IReadOnlyCollection<ScopedRoleAssignment> Assignments);
