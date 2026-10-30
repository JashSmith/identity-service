namespace Avash.Identity.Authorization;

/// <summary>
/// Options for gateway resolution fallback when <c>iam_access</c> is absent/oversized.
/// Microservices that expect scoped assignments point <see cref="GatewayBaseUrl"/> at
/// the Identity Gateway (never at Keycloak directly); the existing
/// <c>BearerTokenDelegatingHandler</c> forwards the inbound bearer token.
/// Binding section: <c>Identity:AccessContext</c> or passed to <c>AddAvashAccessContext</c>.
/// </summary>
public sealed class AccessContextOptions
{
    public const string SectionName = "Identity:AccessContext";

    /// <summary>Base URL of the Identity Gateway, e.g. <c>http://localhost:5080</c>. When null, <c>EnsureLoadedAsync</c> is a no-op.</summary>
    public string? GatewayBaseUrl { get; set; }

    /// <summary>Path of the authoritative access-context endpoint.</summary>
    public string AccessContextPath { get; set; } = "/api/identity/access-context";

    /// <summary>HTTP timeout for the gateway round-trip.</summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(3);
}
