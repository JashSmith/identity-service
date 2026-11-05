namespace Identity.Contracts;

/// <summary>
/// Password credential configuration for a user.
/// </summary>
/// <param name="Password">The plaintext initial password to set.</param>
/// <param name="Temporary">Specifies whether the user must change password upon first login.</param>
public sealed record CredentialRequest(
    string Password,
    bool Temporary);
