using Identity.Contracts;

namespace Identity.Application;

/// <summary>
/// Provisioning interface for creating, updating, and deleting user accounts in Keycloak.
/// </summary>
public interface IUserProvisioningService
{
    /// <summary>
    /// Creates a new user in Keycloak with the requested credentials and profile.
    /// </summary>
    /// <param name="request">The creation parameters.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>The created UserDto.</returns>
    Task<UserDto> CreateUserAsync(CreateUserRequest request, CancellationToken ct);

    /// <summary>
    /// Updates an existing user's profile information in Keycloak.
    /// </summary>
    /// <param name="userId">The Keycloak user ID.</param>
    /// <param name="request">The update payload.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>The updated UserDto, or null if user was not found.</returns>
    Task<UserDto?> UpdateUserAsync(string userId, UpdateUserRequest request, CancellationToken ct);

    /// <summary>
    /// Deletes a user account from Keycloak.
    /// </summary>
    /// <param name="userId">The Keycloak user ID.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>True if deleted or already absent; false on failure.</returns>
    Task<bool> DeleteUserAsync(string userId, CancellationToken ct);
}
