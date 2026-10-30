namespace Identity.Application;

/// <summary>
/// The always-present super-admins group: it exists on every start and holds every permission of every
/// registered application. Roles of Keycloak's own clients (realm-management, account, ...) are never
/// granted, so super-admins administer applications, not Keycloak itself.
/// </summary>
public interface IKeycloakClientRoleProvisioner
{
    /// <summary>Maps every application permission missing from super-admins; returns how many were added.</summary>
    Task<Result<int>> ReconcileAdminAsync(CancellationToken ct);

    /// <summary>Creates super-admins when missing, then reconciles its permissions.</summary>
    Task<Result> EnsureSuperAdminGroupAsync(CancellationToken ct);
}
