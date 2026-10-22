namespace Identity.Domain;

/// <summary>
/// Captures the persistent or cached state of an accepted permission manifest registration for a service.
/// </summary>
/// <param name="ServiceId">The unique identifier of the registering service.</param>
/// <param name="ManifestVersion">The version of the manifest that was accepted.</param>
/// <param name="ManifestHash">The content hash of the accepted manifest.</param>
/// <param name="AcceptedAt">The timestamp when the manifest was accepted by the facade.</param>
/// <param name="DeprecatedPermissions">Any permissions that were previously registered but marked deprecated in this manifest.</param>
public sealed record ManifestRegistrationState(
    string ServiceId,
    string ManifestVersion,
    string ManifestHash,
    DateTimeOffset AcceptedAt,
    IReadOnlyCollection<string> DeprecatedPermissions);
