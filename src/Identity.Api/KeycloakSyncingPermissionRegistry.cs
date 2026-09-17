using Identity.Application;
using Identity.Contracts;

namespace Identity.Api;

/// <summary>
/// Decorator around <see cref="InMemoryPermissionRegistry"/> that, on every manifest registration,
/// best-effort creates matching Keycloak <b>client roles</b> on the owning service client
/// (clientId == serviceId) via <see cref="IKeycloakClientRoleProvisioner"/>.
/// Also ensures a per-client oidc-usermodel-client-role-mapper → permissions claim and
/// auto-maps every new role to the Admin group (key-admins) so admins need no manual grant.
/// Fallback to legacy realm roles via <see cref="IKeycloakRoleProvisioner"/> when the client
/// provisioner is unavailable (tests).
/// Roles are never deleted when they disappear from a manifest (only soft-deprecated locally).
/// </summary>
public sealed class KeycloakSyncingPermissionRegistry(
    InMemoryPermissionRegistry inner,
    IKeycloakRoleProvisioner? legacyProvisioner,
    IKeycloakClientRoleProvisioner? clientProvisioner,
    ILogger<KeycloakSyncingPermissionRegistry> logger) : IPermissionRegistry
{
    // Legacy ctor compat (tests that pass only legacy provisioner)
    public KeycloakSyncingPermissionRegistry(
        InMemoryPermissionRegistry inner,
        IKeycloakRoleProvisioner legacyProvisioner,
        ILogger<KeycloakSyncingPermissionRegistry> logger)
        : this(inner, legacyProvisioner, null, logger) { }

    public async Task<ManifestRegistrationResponse> RegisterAsync(PermissionManifestRequest manifest,
        string authenticatedServiceId, CancellationToken ct)
    {
        ValidateNamespace(manifest, authenticatedServiceId);
        var response = await inner.RegisterAsync(manifest, authenticatedServiceId, ct);

        foreach (var perm in manifest.Permissions)
        {
            try
            {
                bool ok = false;
                if (clientProvisioner is not null)
                {
                    ok = await clientProvisioner.EnsureClientRoleAsync(manifest.ServiceId, perm.Name, perm.Description, ct);
                    if (ok)
                    {
                        await clientProvisioner.EnsureClientRoleMapperAsync(manifest.ServiceId, ct);
                        await clientProvisioner.EnsureAdminGroupMappingAsync(manifest.ServiceId, perm.Name, ct);
                    }
                }
                if (!ok && legacyProvisioner is not null)
                    await legacyProvisioner.EnsureRoleAsync(perm.Name, perm.Description, ct);
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

    private static void ValidateNamespace(PermissionManifestRequest manifest, string authenticatedServiceId)
    {
        // Trust the authenticated service id (from JWT client_id/azp) over the manifest-declared serviceId.
        var effectiveService = string.IsNullOrWhiteSpace(authenticatedServiceId) ? manifest.ServiceId : authenticatedServiceId;
        // Only validate when caller supplied an authenticated service; FacadePermissionRegistrar passes identity-facade.
        if (string.IsNullOrWhiteSpace(effectiveService)) return;

        // Permissive default: any dotted permission is allowed. Strict map for known services.
        var strictPrefixes = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
        {
            ["identity-facade"] = ["Identity.", "identity."],
            ["order-service"] = ["Orders."],
        };
        if (!strictPrefixes.TryGetValue(effectiveService, out var allowed))
            return; // unknown service → permissive (future services add entry here)

        foreach (var p in manifest.Permissions)
        {
            if (allowed.Any(pref => p.Name.StartsWith(pref, StringComparison.Ordinal))) continue;
            throw new InvalidOperationException(
                $"Permission '{p.Name}' not allowed for service '{effectiveService}'. Allowed prefixes: {string.Join(", ", allowed)}");
        }
    }
}
