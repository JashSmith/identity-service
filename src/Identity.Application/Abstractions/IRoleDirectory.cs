using Identity.Contracts;

namespace Identity.Application;

/// <summary>
/// Directory interface for querying realm and client roles from Keycloak.
/// </summary>
public interface IRoleDirectory
{
    /// <summary>
    /// Retrieves a paginated collection of roles.
    /// </summary>
    /// <param name="clientId">Optional client identifier to query client-specific roles; null for realm roles.</param>
    /// <param name="page">1-based page index.</param>
    /// <param name="pageSize">Page size limit.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A paged response containing RoleDto records.</returns>
    Task<PagedResponse<RoleDto>> GetRolesAsync(string? clientId, int page, int pageSize, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves a role by its unique identifier.
    /// </summary>
    /// <param name="id">The role identifier.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The RoleDto or null if not found.</returns>
    Task<RoleDto?> GetRoleAsync(string id, CancellationToken cancellationToken);
}
