namespace Identity.Application;

/// <summary>
/// Provisions Keycloak <b>client roles</b> per owning service client.
/// Replaces the flat realm-role model: each service owns a Keycloak client
/// (clientId == serviceId) and its permissions are client roles on that client.
/// </summary>
public interface IKeycloakClientRoleProvisioner
{
    /// <summary>Ensures the owning client exists (creates it idempotently if missing). Returns its internal UUID.</summary>
    Task<string> EnsureClientAsync(string serviceClientId, CancellationToken ct);

    /// <summary>Ensures a client role exists on the owning client. Idempotent (409 = success). Never throws.</summary>
    Task<bool> EnsureClientRoleAsync(string serviceClientId, string roleName, string? description, CancellationToken ct);

    /// <summary>Ensures one oidc-usermodel-client-role-mapper on the client that aggregates its roles into the permissions claim.</summary>
    Task EnsureClientRoleMapperAsync(string serviceClientId, CancellationToken ct);

    /// <summary>Maps the given client role to the Admin group so administrators automatically receive it.</summary>
    Task<bool> EnsureAdminGroupMappingAsync(string serviceClientId, string roleName, CancellationToken ct);

    /// <summary>Reconciles Admin group: all registered client roles minus already-mapped → add missing. Returns added count.</summary>
    Task<int> ReconcileAdminAsync(CancellationToken ct);

    /// <summary>
    /// Ensures the always-present super-admin group exists with all facade management
    /// permissions and every registered client role. Idempotent; best-effort.
    /// </summary>
    Task EnsureSuperAdminGroupAsync(CancellationToken ct) => Task.CompletedTask;
}
