namespace Identity.Contracts;

/// <summary>Sign-out settings of an application's Keycloak client.</summary>
/// <param name="PostLogoutRedirectUris">Where Keycloak may send users after sign-out (exact URLs).</param>
/// <param name="BackchannelLogoutUrl">Keycloak calls it with a logout token when the user's SSO session ends anywhere.</param>
public sealed record ApplicationLogoutDto(IReadOnlyCollection<string> PostLogoutRedirectUris, string? BackchannelLogoutUrl);

/// <summary>Everything an application needs to connect to the gateway.</summary>
/// <param name="Authority">The gateway URL to configure as authority (never Keycloak's own address).</param>
/// <param name="DiscoveryUrl">The OpenID Connect discovery document (for any standard OIDC library).</param>
/// <param name="Tenant">The tenant id to send (header X-Tenant-Id or ?tenant=); null for the default tenant.</param>
public sealed record ApplicationIntegrationDto(
    string ClientId,
    string Kind,
    string Authority,
    string DiscoveryUrl,
    string? Tenant,
    IReadOnlyCollection<string> RedirectUris,
    ApplicationLogoutDto Logout);
