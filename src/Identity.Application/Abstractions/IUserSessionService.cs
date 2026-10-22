using Identity.Contracts;

namespace Identity.Application;

/// <summary>
/// Service responsible for querying active user sessions (online/offline tracking)
/// and revoking user tokens / active sessions across Keycloak and distributed cache.
/// </summary>
public interface IUserSessionService
{
    /// <summary>
    /// Checks whether the user has at least one active Keycloak session (is online).
    /// </summary>
    /// <param name="userId">The unique Keycloak user ID.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>True if the user is online with active sessions; otherwise, false.</returns>
    Task<bool> IsUserOnlineAsync(string userId, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves all active sessions currently established for the specified user in Keycloak.
    /// </summary>
    /// <param name="userId">The unique Keycloak user ID.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A collection of active UserSessionDto records.</returns>
    Task<IReadOnlyCollection<UserSessionDto>> GetUserSessionsAsync(string userId, CancellationToken cancellationToken);

    /// <summary>
    /// Revokes all active sessions and invalidates tokens for the specified user in Keycloak,
    /// and purges any user-related authorization cache from Redis/memory.
    /// </summary>
    /// <param name="userId">The unique Keycloak user ID.</param>
    /// <param name="reason">An optional administrative reason for revoking user access.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A revocation response indicating operation success and timestamp.</returns>
    Task<RevokeUserTokensResponse> RevokeUserTokensAsync(string userId, string? reason, CancellationToken cancellationToken);
}
