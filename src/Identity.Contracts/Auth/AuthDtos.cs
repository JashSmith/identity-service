namespace Identity.Contracts;

/// <summary>
/// OAuth2 / OpenID Connect token response returned by the gateway token proxy.
/// </summary>
/// <param name="AccessToken">The JWT access token string.</param>
/// <param name="RefreshToken">The refresh token string, if issued.</param>
/// <param name="ExpiresIn">Access token expiration duration in seconds.</param>
/// <param name="TokenType">The token type, default is 'Bearer'.</param>
public sealed record AccessTokenResponse(
    string AccessToken,
    string? RefreshToken,
    int ExpiresIn,
    string TokenType = "Bearer");

/// <summary>
/// Request payload for direct username/password authentication against Keycloak.
/// </summary>
/// <param name="Username">The user's username.</param>
/// <param name="Password">The user's password.</param>
/// <param name="ClientId">The optional client ID (defaults to configured gateway client).</param>
/// <param name="ClientSecret">The optional client secret if required.</param>
public sealed record LoginRequest(
    string Username,
    string Password,
    string? ClientId = null,
    string? ClientSecret = null);

/// <summary>
/// Result of external identity validation (e.g. from upstream SSO provider).
/// </summary>
/// <param name="Provider">The external provider name.</param>
/// <param name="Subject">The external subject identifier.</param>
/// <param name="AllowlistedAttributes">Attributes permitted from external identity.</param>
/// <param name="ExternalRoles">Roles asserted by external identity.</param>
/// <param name="ValidatedAt">Timestamp of validation.</param>
public sealed record ExternalIdentityValidationResult(
    string Provider,
    string Subject,
    IReadOnlyDictionary<string, string> AllowlistedAttributes,
    IReadOnlyCollection<string> ExternalRoles,
    DateTimeOffset ValidatedAt);

/// <summary>
/// Request to exchange an organization external token for an internal token.
/// </summary>
/// <param name="ExternalToken">The external organization token.</param>
public sealed record OrganizationTokenRequest(string ExternalToken);
