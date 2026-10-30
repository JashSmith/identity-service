using Identity.Contracts;

namespace Identity.Application;

/// <summary>
/// Account lifecycle operations beyond create/update/delete: brute-force lockout, credentials (e.g. resetting
/// an OTP device), required actions and action emails. Errors: user.not_found, user.unknown_required_action,
/// credential.not_found, or a Keycloak availability error.
/// </summary>
public interface IUserLifecycleService
{
    Task<Result<UserLockoutDto>> GetLockoutAsync(string userId, CancellationToken ct);

    /// <summary>Clears the failed-login counter and lifts a temporary lockout.</summary>
    Task<Result> UnlockAsync(string userId, CancellationToken ct);

    Task<Result<IReadOnlyCollection<UserCredentialDto>>> GetCredentialsAsync(string userId, CancellationToken ct);

    /// <summary>Removes one credential; removing the OTP credential makes the user enrol a new device.</summary>
    Task<Result> DeleteCredentialAsync(string userId, string credentialId, CancellationToken ct);

    /// <summary>Required actions configured on the realm.</summary>
    Task<Result<IReadOnlyCollection<RequiredActionDto>>> GetRequiredActionCatalogAsync(CancellationToken ct);

    Task<Result<IReadOnlyCollection<string>>> GetRequiredActionsAsync(string userId, CancellationToken ct);

    /// <summary>Only enabled realm actions are accepted.</summary>
    Task<Result> SetRequiredActionsAsync(string userId, IReadOnlyCollection<string> actions, CancellationToken ct);

    Task<Result> SendActionsEmailAsync(string userId, SendActionsEmailRequest request, CancellationToken ct);
}
