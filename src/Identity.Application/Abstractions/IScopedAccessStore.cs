using Identity.Contracts;

namespace Identity.Application;

/// <summary>
/// Persistence abstraction for storing and managing runtime scoped assignments on Keycloak user profiles.
/// </summary>
public interface IScopedAccessStore
{
    /// <summary>
    /// Retrieves the current scoped access document for the specified user.
    /// </summary>
    /// <param name="userId">The unique user ID.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>A ScopedAccessDocument containing the user's scoped roles.</returns>
    Task<ScopedAccessDocument> GetAsync(string userId, CancellationToken ct);

    /// <summary>
    /// Replaces the full scoped access document for a user.
    /// </summary>
    /// <param name="userId">The unique user ID.</param>
    /// <param name="document">The replacement scoped access document.</param>
    /// <param name="ct">Cancellation token.</param>
    Task SetAsync(string userId, ScopedAccessDocument document, CancellationToken ct);

    /// <summary>
    /// Adds a single scoped role assignment to a user.
    /// </summary>
    /// <param name="userId">The unique user ID.</param>
    /// <param name="assignment">The assignment details.</param>
    /// <param name="ct">Cancellation token.</param>
    Task AddAssignmentAsync(string userId, ScopedRoleAssignmentDto assignment, CancellationToken ct);

    /// <summary>
    /// Updates the scope dimension values for a role already assigned to a user.
    /// </summary>
    /// <param name="userId">The unique user ID.</param>
    /// <param name="role">The target role name.</param>
    /// <param name="scopes">The updated dictionary of scope values.</param>
    /// <param name="ct">Cancellation token.</param>
    Task UpdateAssignmentAsync(string userId, string role, IReadOnlyDictionary<string, IReadOnlyCollection<string>> scopes, CancellationToken ct);

    /// <summary>
    /// Removes a scoped role assignment from a user.
    /// </summary>
    /// <param name="userId">The unique user ID.</param>
    /// <param name="role">The role name to unassign.</param>
    /// <param name="ct">Cancellation token.</param>
    Task RemoveAssignmentAsync(string userId, string role, CancellationToken ct);
}

/// <summary>
/// Attributes the identity provider requires on every user profile. A user created without them
/// is locked out of login ("Account is not fully set up"), so the facade validates against this
/// up front and returns field-level errors instead of silently creating an unusable account.
/// </summary>
public interface IUserProfileRequirements
{
    /// <summary>
    /// Retrieves the collection of required user attribute names.
    /// </summary>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>A collection of required attribute names.</returns>
    Task<IReadOnlyCollection<string>> GetRequiredAttributesAsync(CancellationToken ct);
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
