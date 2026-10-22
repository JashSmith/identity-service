namespace Identity.Contracts;

/// <summary>
/// Data transfer object representing a user retrieved from Keycloak.
/// </summary>
/// <param name="Id">The unique user identifier (UUID) assigned by Keycloak.</param>
/// <param name="Username">The unique username of the user.</param>
/// <param name="DisplayName">The formatted display name (e.g. 'First Last') of the user, if available.</param>
/// <param name="Enabled">Indicates whether the user account is enabled.</param>
/// <param name="Attributes">Custom user attributes managed in Keycloak.</param>
/// <param name="IsOnline">Indicates whether the user currently has at least one active Keycloak session.</param>
/// <param name="ActiveSessionsCount">The number of active sessions currently opened for this user.</param>
public sealed record UserDto(
    string Id,
    string Username,
    string? DisplayName,
    bool Enabled,
    IReadOnlyDictionary<string, string[]> Attributes,
    bool? IsOnline = null,
    int? ActiveSessionsCount = null);
