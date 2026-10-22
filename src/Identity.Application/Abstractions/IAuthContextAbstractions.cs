using Identity.Contracts;

namespace Identity.Application;

/// <summary>
/// Provider interface for external identity token exchange.
/// </summary>
public interface IIdentityProvider
{
    /// <summary>
    /// Exchanges an upstream organization token for internal platform access tokens.
    /// </summary>
    /// <param name="externalToken">The external raw token string.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>An AccessTokenResponse.</returns>
    Task<AccessTokenResponse> ExchangeOrganizationTokenAsync(string externalToken, CancellationToken cancellationToken);
}

/// <summary>
/// Validator interface for verifying external identity tokens.
/// </summary>
public interface IExternalIdentityValidator
{
    /// <summary>
    /// Validates an external token and extracts normalized attributes and claims.
    /// </summary>
    /// <param name="externalToken">The external token to validate.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Validation result or null if validation failed.</returns>
    Task<ExternalIdentityValidationResult?> ValidateAsync(string externalToken, CancellationToken cancellationToken);
}

/// <summary>
/// Ambient context representing the current authenticated user making a request.
/// </summary>
public interface ICurrentUserContext
{
    /// <summary>Gets the unique user ID from token claims, if authenticated.</summary>
    string? UserId { get; }

    /// <summary>Gets the username from token claims, if authenticated.</summary>
    string? Username { get; }

    /// <summary>Gets the list of roles assigned to the current user.</summary>
    IReadOnlyCollection<string> Roles { get; }

    /// <summary>Gets the list of permissions granted to the current user.</summary>
    IReadOnlyCollection<string> Permissions { get; }

    /// <summary>Gets the dictionary of token claims.</summary>
    IReadOnlyDictionary<string, string?> Claims { get; }

    /// <summary>Gets the current Keycloak session ID, if present.</summary>
    string? SessionId { get; }

    /// <summary>Gets the timestamp of the current request.</summary>
    DateTimeOffset RequestDateTime { get; }
}

/// <summary>
/// Distributed and local cache invalidation service for user permissions, roles, and tokens.
/// </summary>
public interface ICacheInvalidationService
{
    /// <summary>
    /// Invalidates all cached authorizations, tokens, and session info for the specified user.
    /// </summary>
    /// <param name="userId">The unique user ID.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task InvalidateUserAsync(string userId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Invalidates cached role definitions and scope documents when a business role changes.
    /// </summary>
    /// <param name="roleName">The role name.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task InvalidateRoleAsync(string roleName, CancellationToken cancellationToken = default);
}
