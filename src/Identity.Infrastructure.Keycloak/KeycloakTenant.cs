namespace Identity.Infrastructure.Keycloak;

/// <summary>
/// The Keycloak realm (tenant) the current operation works on. The gateway sets it once per request from the
/// tenant header; background work (the bootstrapper) sets it per tenant. Every Admin API call and admin token
/// uses it, falling back to the configured default realm. It flows with the async call chain (AsyncLocal).
/// </summary>
public static class KeycloakTenant
{
    private static readonly AsyncLocal<KeycloakOptions?> CurrentOptions = new();

    /// <summary>Realm settings of the current tenant, or null for the configured default.</summary>
    public static KeycloakOptions? Current => CurrentOptions.Value;

    /// <summary>Runs the rest of the current async flow against <paramref name="options"/> until disposed.</summary>
    public static IDisposable Use(KeycloakOptions options)
    {
        var previous = CurrentOptions.Value;
        CurrentOptions.Value = options;
        return new Restore(previous);
    }

    /// <summary>The current tenant's options, or <paramref name="fallback"/>.</summary>
    public static KeycloakOptions Resolve(KeycloakOptions fallback) => CurrentOptions.Value ?? fallback;

    private sealed class Restore(KeycloakOptions? previous) : IDisposable
    {
        public void Dispose() => CurrentOptions.Value = previous;
    }
}
