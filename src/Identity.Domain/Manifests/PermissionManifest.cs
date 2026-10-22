namespace Identity.Domain;

/// <summary>
/// Represents the collection of permissions exported and declared by a platform service.
/// </summary>
/// <param name="ServiceId">The unique identifier of the owning service (e.g., 'order-service').</param>
/// <param name="ServiceVersion">The semantic version of the owning service.</param>
/// <param name="ManifestVersion">The monotonic version of the permission manifest itself.</param>
/// <param name="Permissions">The collection of permission definitions declared by the service.</param>
/// <param name="ManifestHash">The cryptographic hash (e.g. SHA-256) of the manifest contents used for idempotency.</param>
public sealed record PermissionManifest(
    string ServiceId,
    string ServiceVersion,
    string ManifestVersion,
    IReadOnlyCollection<PermissionDefinition> Permissions,
    string ManifestHash);
