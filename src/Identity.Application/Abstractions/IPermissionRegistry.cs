using Identity.Contracts;

namespace Identity.Application;

/// <summary>
/// Registry interface for managing dynamic service permissions exported across the platform.
/// </summary>
public interface IPermissionRegistry
{
    /// <summary>
    /// Registers a service permission manifest and mirrors permissions into Keycloak.
    /// </summary>
    /// <param name="manifest">The permission manifest payload.</param>
    /// <param name="authenticatedServiceId">The authenticated identity of the registering service.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A ManifestRegistrationResponse detailing the outcome.</returns>
    Task<ManifestRegistrationResponse> RegisterAsync(PermissionManifestRequest manifest, string authenticatedServiceId, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves all registered permissions, optionally filtered by service.
    /// </summary>
    /// <param name="serviceId">Optional service filter.</param>
    /// <param name="includeDeprecated">Whether to include deprecated permissions.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A collection of registered PermissionDto items.</returns>
    Task<IReadOnlyCollection<PermissionDto>> GetPermissionsAsync(string? serviceId, bool includeDeprecated, CancellationToken cancellationToken);
}
