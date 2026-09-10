using Identity.Application;
using Identity.Contracts;

namespace Identity.Api;

/// <summary>
/// Decorator around <see cref="InMemoryPermissionRegistry"/> that, on every manifest registration,
/// best-effort creates matching Keycloak realm roles via <see cref="IKeycloakRoleProvisioner"/>.
/// This ensures that newly registered permissions are immediately available in token claims
/// (via the <c>oidc-usermodel-realm-role-mapper</c>).
/// <para>
/// Role provisioning failure is NEVER surfaced to the caller — the facade always responds
/// as if registration succeeded. Missing roles are retried on the next registration push.
/// Roles are never deleted when they disappear from a manifest (only soft-deprecated locally).
/// </para>
/// </summary>
public sealed class KeycloakSyncingPermissionRegistry(
    InMemoryPermissionRegistry inner,
    IKeycloakRoleProvisioner roleProvisioner,
    ILogger<KeycloakSyncingPermissionRegistry> logger) : IPermissionRegistry
{
    public async Task<ManifestRegistrationResponse> RegisterAsync(PermissionManifestRequest manifest,
        string authenticatedServiceId, CancellationToken ct)
    {
        var response = await inner.RegisterAsync(manifest, authenticatedServiceId, ct);

        // Best-effort: create every permission as a Keycloak realm role.
        foreach (var perm in manifest.Permissions)
        {
            try
            {
                await roleProvisioner.EnsureRoleAsync(perm.Name, perm.Description, ct);
            }
            catch (Exception ex)
            {
                logger.LogDebug(ex, "Role provisioning failed for {PermissionName} — will retry on next registration",
                    perm.Name);
            }
        }

        return response;
    }

    public Task<IReadOnlyCollection<PermissionDto>> GetPermissionsAsync(string? serviceId, bool includeDeprecated,
        CancellationToken ct)
        => inner.GetPermissionsAsync(serviceId, includeDeprecated, ct);
}
