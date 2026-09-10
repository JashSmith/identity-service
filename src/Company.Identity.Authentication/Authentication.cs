namespace Company.Identity.Authentication;

public sealed class IdentityAuthenticationOptions
{
    public string Authority { get; set; } = string.Empty;
    public string Audience { get; set; } = string.Empty;
    public string[] Audiences { get; set; } = [];
    public TimeSpan ClockSkew { get; set; } = TimeSpan.FromMinutes(1);
    public bool RequireHttpsMetadata { get; set; } = true;
    public string[] ValidAlgorithms { get; set; } = ["RS256"];
    public bool ValidateTokenType { get; set; } = true;

    /// <summary>
    /// When true, the accepted issuer is taken from the OIDC discovery document served at
    /// <see cref="Authority"/> rather than the Authority URL itself. Set this when the
    /// authority is a facade proxying Keycloak discovery/JWKS — consumers then never need
    /// the Keycloak base URL, while the issuer claim inside genuine Keycloak tokens still
    /// validates.
    /// </summary>
    public bool AcceptIssuerFromDiscovery { get; set; }
}