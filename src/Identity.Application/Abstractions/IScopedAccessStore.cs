using Identity.Contracts;

namespace Identity.Application;

/// <summary>
/// The user's own scoped role assignments, exactly as the gateway wrote them. Scopes a user inherits
/// from its groups are never part of this document: reading the merged view and writing it back would
/// copy group scopes onto the user, who would keep them after leaving the group. Use
/// <see cref="Scope.IUserScopeReader"/> for the merged view tokens see.
/// </summary>
public interface IScopedAccessStore
{
    /// <summary>The user's own assignments; user.not_found when the user does not exist.</summary>
    Task<Result<ScopedAccessDocument>> GetAsync(string userId, CancellationToken ct);

    /// <summary>Replaces the user's own assignments (the flat authz.scope.* attributes and the per-role document).</summary>
    Task<Result> SetAsync(string userId, ScopedAccessDocument document, CancellationToken ct);
}

/// <summary>
/// Attributes the identity provider requires on every user profile. A user created without them
/// is locked out of login ("Account is not fully set up"), so the gateway validates against this
/// up front and returns field-level errors instead of silently creating an unusable account.
/// </summary>
public interface IUserProfileRequirements
{
    /// <summary>
    /// Retrieves the collection of required user attribute names.
    /// </summary>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>A collection of required attribute names.</returns>
    Task<Result<IReadOnlyCollection<string>>> GetRequiredAttributesAsync(CancellationToken ct);
}

/// <summary>
/// Configuration options for scoped-access token claim generation and user attribute storage.
/// </summary>
public sealed class ScopedAccessOptions
{
    /// <summary>Gets or sets the Keycloak user attribute key name.</summary>
    public string AttributeName { get; set; } = ScopedAccessConstants.AttributeName;

    /// <summary>Gets or sets the JWT claim name.</summary>
    public string ClaimName { get; set; } = ScopedAccessConstants.ClaimName;

    /// <summary>Gets or sets the maximum inline byte size for claim payloads.</summary>
    public int MaxInlineClaimBytes { get; set; } = ScopedAccessConstants.MaxInlineClaimBytes;
}
