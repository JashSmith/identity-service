using Identity.Contracts;

namespace Identity.Application;

/// <summary>Active sessions of a user and their revocation.</summary>
public interface IUserSessionService
{
    Task<Result<IReadOnlyCollection<UserSessionDto>>> GetUserSessionsAsync(string userId, CancellationToken ct);

    /// <summary>Logs the user out of every session and drops cached authorization data.</summary>
    Task<Result<RevokeUserTokensResponse>> RevokeUserTokensAsync(string userId, string? reason, CancellationToken ct);
}
