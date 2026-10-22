namespace Identity.Contracts;

/// <summary>
/// Request payload for updating existing user details in Keycloak.
/// </summary>
/// <param name="Email">The new email address, or null to keep unchanged.</param>
/// <param name="FirstName">The new first name, or null to keep unchanged.</param>
/// <param name="LastName">The new last name, or null to keep unchanged.</param>
/// <param name="Enabled">The new enabled status, or null to keep unchanged.</param>
public sealed record UpdateUserRequest(
    string? Email,
    string? FirstName,
    string? LastName,
    bool? Enabled);
