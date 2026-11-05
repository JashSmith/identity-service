namespace Identity.Contracts;

/// <summary>
/// Data transfer object describing an exposed permission across the microservices platform.
/// </summary>
/// <param name="Name">The canonical name of the permission (e.g. 'Orders.Read').</param>
/// <param name="Description">The description of the permission.</param>
/// <param name="ServiceId">The service declaring this permission.</param>
/// <param name="ServiceVersion">The declaring service's version.</param>
/// <param name="Deprecated">Specifies if this permission has been deprecated.</param>
/// <param name="KeycloakRoleId">The Keycloak role ID if synced to Keycloak client roles.</param>
public sealed record PermissionDto(
    string Name,
    string Description,
    string ServiceId,
    string ServiceVersion,
    bool Deprecated,
    string? KeycloakRoleId = null);

/// <summary>
/// Definition of a single permission in a service manifest payload.
/// </summary>
/// <param name="Name">The canonical name of the permission.</param>
/// <param name="Description">Human-readable description of what this permission allows.</param>
public sealed record PermissionDefinitionDto(string Name, string Description);

/// <summary>
/// Request payload sent by services during startup or CI/CD to register their permission manifest.
/// </summary>
/// <param name="ServiceId">The registering service ID.</param>
/// <param name="ServiceVersion">The registering service version.</param>
/// <param name="ManifestVersion">The manifest version string.</param>
/// <param name="Permissions">The collection of permissions declared by the service.</param>
/// <param name="ManifestHash">Content hash of the manifest for change detection.</param>
/// <param name="IdempotencyKey">Optional idempotency token for duplicate request suppression.</param>
public sealed record PermissionManifestRequest(
    string ServiceId,
    string ServiceVersion,
    string ManifestVersion,
    IReadOnlyCollection<PermissionDefinitionDto> Permissions,
    string ManifestHash,
    string? IdempotencyKey = null);

/// <summary>
/// Response payload returned after attempting manifest registration.
/// </summary>
/// <param name="ServiceId">The registering service ID.</param>
/// <param name="ManifestVersion">The manifest version that was processed.</param>
/// <param name="ManifestHash">The hash of the manifest.</param>
/// <param name="Accepted">True if registration succeeded and was accepted.</param>
/// <param name="DeprecatedPermissions">Any permissions that became deprecated as a result.</param>
public sealed record ManifestRegistrationResponse(
    string ServiceId,
    string ManifestVersion,
    string ManifestHash,
    bool Accepted,
    IReadOnlyCollection<string> DeprecatedPermissions);
