namespace Identity.Application;

/// <summary>
/// Ensures a Keycloak realm role exists, idempotently. Used by the permission registration
/// path to mirror facade-registered permissions into Keycloak so they appear in token claims.
/// Implementations must never throw — role provisioning is best-effort.
/// </summary>
public interface IKeycloakRoleProvisioner
{
    /// <summary>
    /// Creates the realm role if it does not already exist. Idempotent: a 409/already-exists
    /// response from Keycloak is treated as success.
    /// </summary>
    Task<bool> EnsureRoleAsync(string name, string? description, CancellationToken ct);
}
