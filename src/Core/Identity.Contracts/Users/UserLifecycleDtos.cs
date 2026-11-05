namespace Identity.Contracts;

/// <summary>Brute-force protection state of a user.</summary>
/// <param name="Locked">True while the user is temporarily or permanently locked out after failed logins.</param>
public sealed record UserLockoutDto(bool Locked, int Failures, DateTimeOffset? LastFailure, string? LastFailureIp);

/// <summary>A stored credential (password, OTP device, ...); secrets are never returned.</summary>
public sealed record UserCredentialDto(string Id, string Type, string? Label, DateTimeOffset? CreatedAt);

/// <summary>An action a user can be asked to complete at the next login (e.g. UPDATE_PASSWORD, CONFIGURE_TOTP).</summary>
public sealed record RequiredActionDto(string Alias, string Name, bool Enabled);

/// <summary>Replaces the actions the user must complete at the next login; an empty list clears them.</summary>
public sealed record SetRequiredActionsRequest(IReadOnlyCollection<string> Actions);

/// <summary>
/// Emails the user a link to complete <paramref name="Actions"/> (requires SMTP on the realm).
/// <paramref name="RedirectUri"/> needs <paramref name="ClientId"/> and must be a valid redirect of that client.
/// </summary>
public sealed record SendActionsEmailRequest(
    IReadOnlyCollection<string> Actions,
    int? LifespanSeconds = null,
    string? ClientId = null,
    string? RedirectUri = null);
