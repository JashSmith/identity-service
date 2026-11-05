namespace Identity.Contracts;

/// <summary>
/// Request payload for resetting a user's password in Keycloak.
/// </summary>
/// <param name="Password">The new password.</param>
/// <param name="Temporary">Whether the password is temporary and must be changed on next login.</param>
public sealed record ResetPasswordRequest(
    string Password,
    bool Temporary = false);
