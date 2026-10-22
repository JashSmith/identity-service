using Identity.Contracts;

namespace Identity.Application;

/// <summary>
/// Directory interface for querying users and their effective roles/permissions from Keycloak.
/// </summary>
public interface IUserDirectory
{
    /// <summary>
    /// Retrieves a paginated list of users matching an optional search term.
    /// </summary>
    /// <param name="search">Optional username, email, or name search filter.</param>
    /// <param name="page">The 1-based page index.</param>
    /// <param name="pageSize">The number of records per page.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A paged response containing UserDto records.</returns>
    Task<PagedResponse<UserDto>> GetUsersAsync(string? search, int page, int pageSize, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves a single user by their unique Keycloak ID.
    /// </summary>
    /// <param name="id">The Keycloak user ID.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The UserDto record, or null if not found.</returns>
    Task<UserDto?> GetUserAsync(string id, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves all roles mapped to the specified user.
    /// </summary>
    /// <param name="id">The Keycloak user ID.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A collection of RoleDto records mapped to this user.</returns>
    Task<IReadOnlyCollection<RoleDto>> GetUserRolesAsync(string id, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves all effective permission names granted to the specified user.
    /// </summary>
    /// <param name="id">The Keycloak user ID.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A collection of effective permission DTOs.</returns>
    Task<IReadOnlyCollection<PermissionDto>> GetUserPermissionsAsync(string id, CancellationToken cancellationToken);
}
