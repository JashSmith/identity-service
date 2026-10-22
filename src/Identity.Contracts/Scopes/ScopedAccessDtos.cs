namespace Identity.Contracts;

/// <summary>
/// Central constants for the namespaced scoped-access attribute and claim.
/// Attribute is the Keycloak user-attribute key; claim is the JWT claim consumers read.
/// </summary>
public static class ScopedAccessConstants
{
    /// <summary>The Keycloak user attribute key storing serialized scoped assignments.</summary>
    public const string AttributeName = "iam.scoped_access";

    /// <summary>The JWT token claim name holding scoped authorization data.</summary>
    public const string ClaimName = "iam_access";

    /// <summary>Maximum inline bytes allowed for scoped access claim before offloading.</summary>
    public const int MaxInlineClaimBytes = 4096;
}

/// <summary>
/// A single role bound to arbitrary scope dimensions (e.g. region, branch).
/// </summary>
/// <param name="Role">The role name.</param>
/// <param name="Scopes">The dictionary of scope dimensions and allowed values.</param>
public sealed record ScopedRoleAssignment(
    string Role,
    IReadOnlyDictionary<string, IReadOnlyCollection<string>> Scopes);

/// <summary>
/// The full set of scoped assignments for a user. Serialized as a JSON array of
/// <see cref="ScopedRoleAssignment"/> and stored in the Keycloak attribute <see cref="ScopedAccessConstants.AttributeName"/>.
/// </summary>
/// <param name="Assignments">The collection of scoped role assignments.</param>
public sealed record ScopedAccessDocument(
    IReadOnlyCollection<ScopedRoleAssignment> Assignments)
{
    /// <summary>An empty scoped access document instance.</summary>
    public static ScopedAccessDocument Empty { get; } = new(Array.Empty<ScopedRoleAssignment>());
}

/// <summary>
/// DTO for assigning scopes to a role.
/// </summary>
/// <param name="Role">The target role name.</param>
/// <param name="Scopes">The scope dictionary.</param>
public sealed record ScopedRoleAssignmentDto(
    string Role,
    [property: System.Text.Json.Serialization.JsonConverter(typeof(ScopeDictionaryConverter))]
    IReadOnlyDictionary<string, IReadOnlyCollection<string>> Scopes);

/// <summary>
/// Request payload to replace all scoped assignments for a user.
/// </summary>
/// <param name="Assignments">The replacement collection of assignments.</param>
public sealed record SetScopedAccessRequest(
    IReadOnlyCollection<ScopedRoleAssignmentDto> Assignments);

/// <summary>
/// Response payload returning a user's scoped assignments.
/// </summary>
/// <param name="UserId">The user identifier.</param>
/// <param name="Assignments">The assigned scoped roles.</param>
public sealed record ScopedAccessResponse(
    string UserId,
    IReadOnlyCollection<ScopedRoleAssignment> Assignments);

/// <summary>
/// Aggregated access context representing the authenticated caller's effective access.
/// </summary>
/// <param name="UserId">The user ID if authenticated.</param>
/// <param name="Username">The username if authenticated.</param>
/// <param name="Permissions">Effective permission strings.</param>
/// <param name="Assignments">Effective scoped assignments.</param>
public sealed record AccessContextResponse(
    string? UserId,
    string? Username,
    IReadOnlyCollection<string> Permissions,
    IReadOnlyCollection<ScopedRoleAssignment> Assignments,
    IReadOnlyDictionary<string, IReadOnlyCollection<string>>? Scopes = null);
