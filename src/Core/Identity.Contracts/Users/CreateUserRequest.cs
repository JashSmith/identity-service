namespace Identity.Contracts;

/// <summary>
/// Request payload for creating a new user in Keycloak with optional credentials and scoped assignments.
/// </summary>
/// <param name="Username">The unique username for the new account.</param>
/// <param name="Email">The optional email address for the user.</param>
/// <param name="FirstName">The first name of the user.</param>
/// <param name="LastName">The last name of the user.</param>
/// <param name="Enabled">Specifies whether the user should be initially enabled.</param>
/// <param name="Credentials">The initial password configuration for the user.</param>
/// <param name="Assignments">The initial business roles and runtime scope assignments.</param>
public sealed record CreateUserRequest(
    string Username,
    string? Email,
    string? FirstName,
    string? LastName,
    bool Enabled,
    CredentialRequest? Credentials,
    IReadOnlyCollection<ScopedRoleAssignmentDto>? Assignments);
