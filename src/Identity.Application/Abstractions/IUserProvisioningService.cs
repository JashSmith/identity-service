using Identity.Contracts;

namespace Identity.Application;

/// <summary>
/// Writes users in the identity provider. Failures are errors: user.not_found, user.conflict
/// (username or email taken), user.rejected (e.g. password policy), or a Keycloak availability error.
/// </summary>
public interface IUserProvisioningService
{
    Task<Result<UserDto>> GetAsync(string userId, CancellationToken ct);

    Task<Result<UserDto>> CreateUserAsync(CreateUserRequest request, CancellationToken ct);

    /// <summary>Applies the non-null fields of <paramref name="request"/> and keeps everything else.</summary>
    Task<Result<UserDto>> UpdateUserAsync(string userId, UpdateUserRequest request, CancellationToken ct);

    Task<Result> DeleteUserAsync(string userId, CancellationToken ct);

    Task<Result> ResetPasswordAsync(string userId, string newPassword, bool temporary, CancellationToken ct);
}
