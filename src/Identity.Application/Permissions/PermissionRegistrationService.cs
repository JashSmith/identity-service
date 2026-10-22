using Identity.Contracts;

namespace Identity.Application;

/// <summary>
/// Domain service that orchestrates the registration and validation of service permission manifests.
/// </summary>
/// <param name="registry">The underlying permission registry implementation.</param>
public sealed class PermissionRegistrationService(IPermissionRegistry registry)
{
    /// <summary>
    /// Registers a permission manifest for an authenticated service.
    /// </summary>
    /// <param name="manifest">The manifest to register.</param>
    /// <param name="authenticatedServiceId">The authenticated service ID.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A ManifestRegistrationResponse.</returns>
    public Task<ManifestRegistrationResponse> RegisterAsync(PermissionManifestRequest manifest,
        string authenticatedServiceId, CancellationToken cancellationToken)
        => registry.RegisterAsync(manifest, authenticatedServiceId, cancellationToken);
}
