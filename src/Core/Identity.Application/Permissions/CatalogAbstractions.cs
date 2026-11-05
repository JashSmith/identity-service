using Identity.Contracts;

namespace Identity.Application.Permissions;

/// <summary>
/// Applications whose permissions the gateway manages (Keycloak clients marked <c>iam.application</c>).
/// Errors: application.not_found, application.already_exists, application.reserved, or a Keycloak error.
/// </summary>
public interface IApplicationCatalog
{
    Task<Result<IReadOnlyCollection<ApplicationDto>>> ListAsync(CancellationToken ct);
    Task<Result<ApplicationDto>> GetAsync(string clientId, CancellationToken ct);

    /// <summary>Creates the client, its permission claim mapper, and returns its secret once.</summary>
    Task<Result<ApplicationSecretResponse>> CreateAsync(CreateApplicationRequest request, CancellationToken ct);

    Task<Result<ApplicationDto>> UpdateAsync(string clientId, UpdateApplicationRequest request, CancellationToken ct);

    /// <summary>Deletes the client and, with it, every permission it owns.</summary>
    Task<Result> DeleteAsync(string clientId, CancellationToken ct);

    Task<Result<ApplicationSecretResponse>> RotateSecretAsync(string clientId, CancellationToken ct);

    /// <summary>Ensures the shared permissions client scope with one prefixed mapper per application.</summary>
    Task<Result> EnsurePermissionClaimsAsync(CancellationToken ct);
}

/// <summary>
/// The permission catalog, stored as client roles of each application (role attributes hold display name,
/// source and deprecation). Errors: permission.not_found, permission.already_exists, permission.invalid,
/// application.not_found, application.not_registered.
/// </summary>
public interface IPermissionCatalog
{
    Task<Result<IReadOnlyCollection<CatalogPermissionDto>>> ListAsync(string? application, bool includeDeprecated, CancellationToken ct);
    Task<Result<PermissionTreeDto>> GetTreeAsync(bool includeDeprecated, CancellationToken ct);
    Task<Result<CatalogPermissionDto>> CreateAsync(string application, CreateCatalogPermissionRequest request, CancellationToken ct);
    Task<Result<CatalogPermissionDto>> UpdateAsync(string application, string localName, UpdateCatalogPermissionRequest request, CancellationToken ct);
    Task<Result> DeleteAsync(string application, string localName, CancellationToken ct);

    /// <summary>
    /// Synchronises the manifest of <paramref name="application"/> (the authenticated caller): creates new
    /// permissions, refreshes existing ones and marks permissions that disappeared as deprecated (never deleted).
    /// </summary>
    Task<Result<ManifestRegistrationResponse>> RegisterManifestAsync(string application, PermissionManifestRequest manifest, CancellationToken ct);
}
